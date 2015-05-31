// Copyright 2014 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "common/logging/log.h"

#include "core/hle/hle.h"
#include "core/hle/service/ldr_ro.h"
#include "common/file_util.h"

////////////////////////////////////////////////////////////////////////////////////////////////////
// Namespace LDR_RO

namespace LDR_RO {

struct SegmentTableEntry {
    u32 segment_offset;
    u32 segment_size;
    u32 segment_id;
};

struct Patch {
    u32 offset;
    u8 type;
    u8 unk;
    u8 unk2;
    u8 unk3;
    u32 x;

    u8 GetTargetSegment() { return offset & 0xF; }
    u32 GetSegmentOffset() { return offset >> 4; }
};

struct Unk3Patch {
    u32 segment_offset;
    u32 patches_offset;

    u8 GetTargetSegment() { return segment_offset & 0xF; }
    u32 GetSegmentOffset() { return segment_offset >> 4; }
};

struct Unk2TableEntry {
    u32 offset_or_index; ///< Index in the CRO's segment offset table (unk1) for table1 entries, or segment_offset for table2 entries
    u32 patches_offset;
};

struct Unk2Patch {
    u32 string_offset;
    u32 table1_offset;
    u32 table1_num;
    u32 table2_offset;
    u32 table2_num;

    Unk2TableEntry* GetTable1Entry(u32 index);
    Unk2TableEntry* GetTable2Entry(u32 index);
};

Unk2TableEntry* Unk2Patch::GetTable1Entry(u32 index) {
    return reinterpret_cast<Unk2TableEntry*>(Memory::GetPointer(table1_offset) + sizeof(Unk2TableEntry) * index);
}

Unk2TableEntry* Unk2Patch::GetTable2Entry(u32 index) {
    return reinterpret_cast<Unk2TableEntry*>(Memory::GetPointer(table2_offset) + sizeof(Unk2TableEntry) * index);
}

struct ExportTableEntry {
    u32 name_offset;
    u32 segment_offset;

    u8 GetTargetSegment() { return segment_offset & 0xF; }
    u32 GetSegmentOffset() { return segment_offset >> 4; }
};

struct ImportTableEntry {
    u32 name_offset;
    u32 symbol_offset;
};

struct ExportedSymbol {
    std::string name;
    u32 cro_base;
    u32 cro_offset;
};

struct CROHeader {
    u8 sha2_hash[0x80];
    char magic[4];
    u32 name_offset;
    u32 previous_cro;
    u32 next_cro;
    u32 file_size;
    INSERT_PADDING_WORDS(0x6);
    u32 segment_offset;
    u32 code_offset;
    u32 code_size;
    u32 unk_offset;
    u32 unk_size;
    u32 module_name_offset;
    u32 module_name_size;
    u32 segment_table_offset;
    u32 segment_table_num;
    u32 export_table_offset;
    u32 export_table_num;
    u32 unk1_offset;
    u32 unk1_size;
    u32 export_strings_offset;
    u32 export_strings_num;
    u32 export_tree_offset;
    u32 export_tree_num;
    u32 unk2_offset;
    u32 unk2_num;
    u32 import_patches_offset;
    u32 import_patches_num;
    u32 import_table1_offset;
    u32 import_table1_num;
    u32 import_table2_offset;
    u32 import_table2_num;
    u32 import_table3_offset;
    u32 import_table3_num;
    u32 import_strings_offset;
    u32 import_strings_num;
    u32 unk3_offset;
    u32 unk3_num;
    u32 relocation_patches_offset;
    u32 relocation_patches_num;
    u32 unk4_offset; /// More patches?
    u32 unk4_num;

    u8 GetImportPatchesTargetSegment() { return segment_offset & 0xF; }
    u8 GetImportPatchesSegmentOffset() { return segment_offset >> 4; }

    SegmentTableEntry* GetSegmentTableEntry(u32 index, bool relocated = false);
    void RelocateSegmentsTable(u32 base, u32 data_section0, u32 data_section1);

    ExportTableEntry* GetExportTableEntry(u32 index);
    void RelocateExportsTable(u32 base);

    Patch* GetImportPatch(u32 index);

    ImportTableEntry* GetImportTable1Entry(u32 index);
    void RelocateImportTable1(u32 base);

    ImportTableEntry* GetImportTable2Entry(u32 index);
    void RelocateImportTable2(u32 base);

    ImportTableEntry* GetImportTable3Entry(u32 index);
    void RelocateImportTable3(u32 base);

    Unk3Patch* GetUnk3PatchEntry(u32 index);

    Patch* GetRelocationPatchEntry(u32 index);

    Unk2Patch* GetUnk2PatchEntry(u32 index);

    u32 GetUnk1TableEntry(u32 index);

    void RelocateUnk2Patches(u32 base);

    void RelocateOffsets(u32 base);
};

static std::unordered_map<std::string, ExportedSymbol> loaded_exports;
static std::vector<u32> loaded_cros;

SegmentTableEntry* CROHeader::GetSegmentTableEntry(u32 index, bool relocated) {
    if (relocated)
        return reinterpret_cast<SegmentTableEntry*>(Memory::GetPointer(segment_table_offset + sizeof(SegmentTableEntry) * index));

    return reinterpret_cast<SegmentTableEntry*>(reinterpret_cast<u8*>(this) + segment_table_offset + sizeof(SegmentTableEntry) * index);
}

void CROHeader::RelocateSegmentsTable(u32 base, u32 data_section0, u32 data_section1) {
    for (int i = 0; i < segment_table_num; ++i) {
        SegmentTableEntry* entry = GetSegmentTableEntry(i);
        if (entry->segment_id == 2) {
            entry->segment_offset = data_section0;
        } else if (entry->segment_id == 3) {
            entry->segment_offset = data_section1;
        } else if (entry->segment_offset) {
            entry->segment_offset += base;
        }
    }
}

u32 CROHeader::GetUnk1TableEntry(u32 index) {
    return *reinterpret_cast<u32*>(reinterpret_cast<u8*>(this) + unk1_offset + sizeof(u32) * index);
}

ExportTableEntry* CROHeader::GetExportTableEntry(u32 index) {
    return reinterpret_cast<ExportTableEntry*>(reinterpret_cast<u8*>(this) + export_table_offset + sizeof(ExportTableEntry) * index);
}

void CROHeader::RelocateExportsTable(u32 base) {
    for (int i = 0; i < export_table_num; ++i) {
        ExportTableEntry* entry = GetExportTableEntry(i);
        if (entry->name_offset)
            entry->name_offset += base;
    }
}

Patch* CROHeader::GetImportPatch(u32 index) {
    return reinterpret_cast<Patch*>(reinterpret_cast<u8*>(this) + import_patches_offset + sizeof(Patch) * index);
}

ImportTableEntry* CROHeader::GetImportTable1Entry(u32 index) {
    return reinterpret_cast<ImportTableEntry*>(reinterpret_cast<u8*>(this) + import_table1_offset + sizeof(ImportTableEntry) * index);
}

ImportTableEntry* CROHeader::GetImportTable2Entry(u32 index) {
    return reinterpret_cast<ImportTableEntry*>(reinterpret_cast<u8*>(this) + import_table2_offset + sizeof(ImportTableEntry) * index);
}

ImportTableEntry* CROHeader::GetImportTable3Entry(u32 index) {
    return reinterpret_cast<ImportTableEntry*>(reinterpret_cast<u8*>(this) + import_table3_offset + sizeof(ImportTableEntry) * index);
}

void CROHeader::RelocateImportTable1(u32 base) {
    for (int i = 0; i < import_table1_num; ++i) {
        ImportTableEntry* entry = GetImportTable1Entry(i);
        if (entry->name_offset)
            entry->name_offset += base;
        if (entry->symbol_offset)
            entry->symbol_offset += base;
    }
}

void CROHeader::RelocateImportTable2(u32 base) {
    for (int i = 0; i < import_table2_num; ++i) {
        ImportTableEntry* entry = GetImportTable2Entry(i);
        if (entry->symbol_offset)
            entry->symbol_offset += base;
    }
}

void CROHeader::RelocateImportTable3(u32 base) {
    for (int i = 0; i < import_table3_num; ++i) {
        ImportTableEntry* entry = GetImportTable3Entry(i);
        if (entry->symbol_offset)
            entry->symbol_offset += base;
    }
}

void CROHeader::RelocateUnk2Patches(u32 base) {
    for (int i = 0; i < unk2_num; ++i) {
        Unk2Patch* entry = GetUnk2PatchEntry(i);
        if (entry->string_offset)
            entry->string_offset += base;
        if (entry->table1_offset)
            entry->table1_offset += base;
        if (entry->table2_offset)
            entry->table2_offset += base;
    }
}

Unk3Patch* CROHeader::GetUnk3PatchEntry(u32 index) {
    return reinterpret_cast<Unk3Patch*>(reinterpret_cast<u8*>(this) + unk3_offset * sizeof(Unk3Patch) * index);
}

Patch* CROHeader::GetRelocationPatchEntry(u32 index) {
    return reinterpret_cast<Patch*>(reinterpret_cast<u8*>(this) + relocation_patches_offset + sizeof(Patch) * index);
}

Unk2Patch* CROHeader::GetUnk2PatchEntry(u32 index) {
    return reinterpret_cast<Unk2Patch*>(reinterpret_cast<u8*>(this) + unk2_offset + sizeof(Unk2Patch) * index);
}

void CROHeader::RelocateOffsets(u32 base) {
    segment_table_offset += base;
    export_strings_offset += base;
    export_table_offset += base;
    export_tree_offset += base;
    name_offset += base;
    unk_offset += base;
}

static void ApplyPatch(Patch* patch, u32 patch_base, u32 patch_address) {
    switch (patch->type) {
        case 2:
            Memory::Write32(patch_address, patch_base + patch->x);
            break;
        default:
            LOG_CRITICAL(Service_APT, "Unknown patch type %u", patch->type);
    }
}

static void ApplyImportPatches(CROHeader* header, u32 base) {
    SegmentTableEntry* base_segment = header->GetSegmentTableEntry(header->GetImportPatchesTargetSegment());
    u32 patch_base = base_segment->segment_offset + header->GetImportPatchesSegmentOffset();
    for (int i = 0; i < header->import_patches_num; ++i) {
        Patch* patch = header->GetImportPatch(i);
        SegmentTableEntry* target_segment = header->GetSegmentTableEntry(patch->GetTargetSegment());
        ApplyPatch(patch, patch_base, target_segment->segment_offset + patch->GetSegmentOffset());
    }
}

static void ApplyListPatches(CROHeader* header, Patch* first_patch, u32 patch_base) {
    Patch* current_patch = first_patch;

    do {
        SegmentTableEntry* target_segment = header->GetSegmentTableEntry(current_patch->GetTargetSegment());
        ApplyPatch(current_patch, patch_base, target_segment->segment_offset + current_patch->GetSegmentOffset());
    } while (!(current_patch++)->unk);
    
    first_patch->unk2 = 1;
}

static void ApplyUnk3Patches(CROHeader* header, u32 base) {
    for (int i = 0; i < header->unk3_num; ++i) {
        Unk3Patch* patch = header->GetUnk3PatchEntry(i);
        SegmentTableEntry* segment = header->GetSegmentTableEntry(patch->GetTargetSegment());
        u32 patch_base = segment->segment_offset + patch->GetSegmentOffset();
        u32 patches_table = base + patch->patches_offset;
        
        Patch* first_patch = reinterpret_cast<Patch*>(Memory::GetPointer(patches_table));
        ApplyListPatches(header, first_patch, patch_base);
    }
}

static void ApplyRelocationPatches(CROHeader* header, u32 base) {
    for (int i = 0; i < header->relocation_patches_num; ++i) {
        Patch* patch = header->GetRelocationPatchEntry(i);
        u32 segment_id = patch->GetTargetSegment();
        SegmentTableEntry* target_segment = header->GetSegmentTableEntry(segment_id);
        SegmentTableEntry* base_segment = header->GetSegmentTableEntry(patch->unk);
        u32 patch_address = target_segment->segment_offset + patch->GetSegmentOffset();
        ApplyPatch(patch, base_segment->segment_offset, patch_address);
    }
}

static void ApplyExitPatches(CROHeader* header, u32 base) {
    // Find the "__aeabi_atexit" in the import table 1
    for (int i = 0; i < header->import_table1_num; ++i) {
        ImportTableEntry* entry = header->GetImportTable1Entry(i);
        // The name is already relocated
        char* entry_name = reinterpret_cast<char*>(Memory::GetPointer(entry->name_offset));
        if (!strcmp(entry_name, "__aeabi_atexit")) {
            // Only apply these patches if some previous CRO exports "nnroAeabiAtexit_"
            auto export = loaded_exports.find("nnroAeabiAtexit_");
            if (export == loaded_exports.end())
                return;

            // Patch it!
            Patch* first_patch = reinterpret_cast<Patch*>(Memory::GetPointer(entry->symbol_offset));
            ApplyListPatches(header, first_patch, export->second.cro_offset);
            return;
        }
    }
    LOG_ERROR(Service_LDR, "Could not find __aeabi_atexit in the CRO imports!");
}

static void ApplyImportTable1Patches(CROHeader* header, u32 base, bool relocated) {
    for (int i = 0; i < header->import_table1_num; ++i) {
        ImportTableEntry* entry = header->GetImportTable1Entry(i);
        Patch* patch = reinterpret_cast<Patch*>(Memory::GetPointer(entry->symbol_offset));
        if (!patch->unk2) {
            // The name offset is already relocated
            std::string entry_name = reinterpret_cast<char*>(Memory::GetPointer(entry->name_offset));
            auto export = loaded_exports.find(entry_name);
            if (export == loaded_exports.end())
                continue;
            
            u32 patch_base = export->second.cro_offset;

            Patch* first_patch = reinterpret_cast<Patch*>(Memory::GetPointer(entry->symbol_offset));
            ApplyListPatches(header, first_patch, patch_base);
        }
    }
}

static u32 GetCROBaseByName(char* name) {
    for (u32 base : loaded_cros) {
        CROHeader* header = reinterpret_cast<CROHeader*>(Memory::GetPointer(base));
        if (!strcmp(reinterpret_cast<char*>(header) + header->name_offset, name))
            return base;
    }
    return 0;
}

static void ApplyUnk2Patches(CROHeader* header, u32 base, bool relocated) {
    for (int i = 0; i < header->unk2_num; ++i) {
        Unk2Patch* entry = header->GetUnk2PatchEntry(i);
        u32 cro_base = GetCROBaseByName(reinterpret_cast<char*>(Memory::GetPointer(entry->string_offset)));
        if (cro_base == 0)
            continue;

        CROHeader* patch_cro = reinterpret_cast<CROHeader*>(Memory::GetPointer(cro_base));
        // Apply the patches from the first table
        for (int j = 0; j < entry->table1_num; ++j) {
            Unk2TableEntry* table1_entry = entry->GetTable1Entry(j);
            u32 unk1_table_entry = header->GetUnk1TableEntry(table1_entry->offset_or_index);
            u32 target_segment_id = unk1_table_entry & 0xF;
            u32 target_segment_offset = unk1_table_entry >> 4;
            SegmentTableEntry* target_base_segment = patch_cro->GetSegmentTableEntry(target_segment_id, relocated);

            Patch* first_patch = reinterpret_cast<Patch*>(Memory::GetPointer(base + table1_entry->patches_offset));
            ApplyListPatches(header, first_patch, target_base_segment->segment_offset + target_segment_offset);
        }

        // Apply the patches from the second table
        for (int j = 0; j < entry->table2_num; ++j) {
            Unk2TableEntry* table2_entry = entry->GetTable2Entry(j);
            u32 target_segment_id = table2_entry->offset_or_index & 0xF;
            u32 target_segment_offset = table2_entry->offset_or_index >> 4;
            SegmentTableEntry* target_base_segment = patch_cro->GetSegmentTableEntry(target_segment_id, relocated);

            Patch* first_patch = reinterpret_cast<Patch*>(Memory::GetPointer(base + table2_entry->patches_offset));
            ApplyListPatches(header, first_patch, target_base_segment->segment_offset + target_segment_offset);
        }
    }
}

static void LoadExportsTable(CROHeader* header, u32 base) {
    for (int i = 0; i < header->export_table_num; ++i) {
        ExportTableEntry* entry = header->GetExportTableEntry(i);
        SegmentTableEntry* target_segment = header->GetSegmentTableEntry(entry->GetTargetSegment());
        ExportedSymbol export;
        export.cro_base = base;
        export.cro_offset = target_segment->segment_offset + entry->GetSegmentOffset();
        export.name = reinterpret_cast<char*>(Memory::GetPointer(entry->name_offset));
        loaded_exports[export.name] = export;
    }
}

static void LoadCRO(u32 base, u8* cro, bool relocate_segments, u32 data_section0, u32 data_section1) {
    CROHeader* header = reinterpret_cast<CROHeader*>(cro);
    memcpy(header->magic, "FIXD", 4);

    for (int i = 0; i < header->file_size; ++i) {
        u32* d = (u32*)header + i;
        if (*d == 0x2020E || *d == 0x2020D)
            __debugbreak();
    }
    if (relocate_segments) {
        // Relocate segments
        header->RelocateSegmentsTable(base, data_section0, data_section1);
    }

    // Rebase export table
    header->RelocateExportsTable(base);

    // Rebase unk2
    header->RelocateUnk2Patches(base);

    // Apply import patches
    ApplyImportPatches(header, base);

    // Rebase import table 1 name & symbol offsets
    header->RelocateImportTable1(base);

    // Rebase import tables 2 & 3 symbol offsets
    header->RelocateImportTable2(base);
    header->RelocateImportTable3(base);

    // Apply unk3 patches
    ApplyUnk3Patches(header, base);

    // Apply relocation patches
    ApplyRelocationPatches(header, base);

    // Apply import table 1 patches
    ApplyExitPatches(header, base);

    // Import Table 1
    ApplyImportTable1Patches(header, base, false);

    // Apply unk2 patches
    ApplyUnk2Patches(header, base, false);

    // Load exports
    LoadExportsTable(header, base);

    // Retroactively apply import table 1 patches to the previous CROs
    // Retroactively apply unk2 patches to the previous CROs
    for (u32 cro_base : loaded_cros) {
        CROHeader* cro_header = reinterpret_cast<CROHeader*>(Memory::GetPointer(cro_base));
        ApplyImportTable1Patches(cro_header, cro_base, true);
        ApplyUnk2Patches(header, cro_base, true);
    }

    // Relocate all offsets
    header->RelocateOffsets(base);

    loaded_cros.push_back(base);
}

/**
 * LDR_RO::Initialize service function
 *  Inputs:
 *      1 : CRS buffer pointer
 *      2 : CRS Size
 *      3 : Process memory address where the CRS will be mapped
 *      4 : Value, must be zero
 *      5 : KProcess handle
 *  Outputs:
 *      0 : Return header
 *      1 : Result of function, 0 on success, otherwise error code
 */
static void Initialize(Service::Interface* self) {
    u32* cmd_buff = Kernel::GetCommandBuffer();
    u8* crs_buffer_ptr = Memory::GetPointer(cmd_buff[1]);
    u32 crs_size       = cmd_buff[2];
    u8* address        = Memory::GetPointer(cmd_buff[3]);
    u32 value          = cmd_buff[4];
    u32 process        = cmd_buff[5];

    if (value != 0) {
        LOG_ERROR(Service_LDR, "This value should be zero, but is actually %u!", value);
    }

    loaded_exports.clear();
    loaded_cros.clear();

    memcpy(address, crs_buffer_ptr, crs_size);

    LoadCRO(cmd_buff[3], address, false, 0, 0);

    // TODO(purpasmart96): Verify return header on HW

    cmd_buff[1] = RESULT_SUCCESS.raw; // No error

    LOG_WARNING(Service_LDR, "(STUBBED) called. crs_buffer_ptr=0x%08X, crs_size=0x%08X, address=0x%08X, value=0x%08X, process=0x%08X",
                crs_buffer_ptr, crs_size, address, value, process);
}

/**
 * LDR_RO::LoadCRR service function
 *  Inputs:
 *      1 : CRS buffer pointer
 *      2 : CRS Size
 *      3 : Value, must be zero
 *      4 : KProcess handle
 *  Outputs:
 *      0 : Return header
 *      1 : Result of function, 0 on success, otherwise error code
 */
static void LoadCRR(Service::Interface* self) {
    u32* cmd_buff = Kernel::GetCommandBuffer();
    u32 crs_buffer_ptr = cmd_buff[1];
    u32 crs_size       = cmd_buff[2];
    u32 value          = cmd_buff[3];
    u32 process        = cmd_buff[4];

    if (value != 0) {
        LOG_ERROR(Service_LDR, "This value should be zero, but is actually %u!", value);
    }

    // TODO(purpasmart96): Verify return header on HW

    cmd_buff[1] = RESULT_SUCCESS.raw; // No error

    LOG_WARNING(Service_LDR, "(STUBBED) called. crs_buffer_ptr=0x%08X, crs_size=0x%08X, value=0x%08X, process=0x%08X",
                crs_buffer_ptr, crs_size, value, process);
}

static void LoadExeCRO(Service::Interface* self) {
    u32* cmd_buff = Kernel::GetCommandBuffer();
    u32 base = cmd_buff[2];
    u8* dst = Memory::GetPointer(base);
    u32 size = cmd_buff[3];

    memcpy(dst, Memory::GetPointer(cmd_buff[1]), size);

    LoadCRO(base, dst, true, cmd_buff[4], cmd_buff[7]);

    cmd_buff[1] = 0;
    cmd_buff[2] = 0;
    LOG_WARNING(Service_APT, "Loading CRO");
}

const Interface::FunctionInfo FunctionTable[] = {
    {0x000100C2, Initialize,            "Initialize"},
    {0x00020082, LoadCRR,               "LoadCRR"},
    {0x00030042, nullptr,               "UnloadCCR"},
    {0x000402C2, LoadExeCRO,            "LoadExeCRO"},
    {0x000500C2, nullptr,               "LoadCROSymbols"},
    {0x00060042, nullptr,               "CRO_Load?"},
    {0x00070042, nullptr,               "LoadCROSymbols"},
    {0x00080042, nullptr,               "Shutdown"},
    {0x000902C2, nullptr,               "LoadExeCRO_New?"},
};

////////////////////////////////////////////////////////////////////////////////////////////////////
// Interface class

Interface::Interface() {
    Register(FunctionTable);
}

} // namespace
