// Copyright 2014 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "common/logging/log.h"

#include "core/hle/hle.h"
#include "core/hle/service/ldr_ro.h"
#include "core/hle/kernel/process.h"
#include "core/hle/kernel/vm_manager.h"
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

struct ExportTreeEntry {
    u16 segment_offset;
    u16 unk;
    u16 unk2;
    u16 export_table_id;

    u8 GetTargetSegment() { return segment_offset & 0x7; }
    u32 GetSegmentOffset() { return segment_offset >> 3; }
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
    u32 next_cro;
    u32 previous_cro;
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
    void RelocateSegmentsTable(u32 base, u32 data_section0, u32 data_section1, u32& prev_data_section0);

    ExportTableEntry* GetExportTableEntry(u32 index);
    void RelocateExportsTable(u32 base);

    ExportTreeEntry* GetExportTreeEntry(u32 index);

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

void CROHeader::RelocateSegmentsTable(u32 base, u32 data_section0, u32 data_section1, u32& prev_data_section0) {
    prev_data_section0 = 0;
    for (int i = 0; i < segment_table_num; ++i) {
        SegmentTableEntry* entry = GetSegmentTableEntry(i);
        if (entry->segment_id == 2) {
            prev_data_section0 = entry->segment_offset;
            entry->segment_offset = data_section0;
        } else if (entry->segment_id == 3) {
            entry->segment_offset = data_section1;
        } else if (entry->segment_offset) {
            entry->segment_offset += base;
        }
    }
}

ExportTreeEntry* CROHeader::GetExportTreeEntry(u32 index) {
    return reinterpret_cast<ExportTreeEntry*>(reinterpret_cast<u8*>(this) + export_tree_offset + sizeof(ExportTreeEntry) * index);
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
    memcpy(magic, "FIXD", 4);
    segment_table_offset += base;
    export_strings_offset += base;
    export_table_offset += base;
    export_tree_offset += base;
    name_offset += base;
    unk_offset += base;
}

static void ApplyPatch(Patch* patch, u32 patch_base, u32 patch_address, u32* patch_address1 = nullptr) {

    if (!patch_address1)
        patch_address1 = &patch_address;

    switch (patch->type) {
        case 2:
            Memory::Write32(patch_address, patch_base + patch->x);
            break;
        case 3:
            Memory::Write32(patch_address, patch_base + patch->x - *patch_address1);
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

static void ApplyListPatches(CROHeader* header, Patch* first_patch, u32 patch_base, bool relocated = false) {
    Patch* current_patch = first_patch;

    do {
        SegmentTableEntry* target_segment = header->GetSegmentTableEntry(current_patch->GetTargetSegment(), relocated);
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

static void ApplyRelocationPatches(CROHeader* header, u32 base, u32 section0) {
    for (int i = 0; i < header->relocation_patches_num; ++i) {
        Patch* patch = header->GetRelocationPatchEntry(i);
        u32 segment_id = patch->GetTargetSegment();
        SegmentTableEntry* target_segment = header->GetSegmentTableEntry(segment_id);
        u32 target_segment_offset = target_segment->segment_offset;

        if (segment_id == 2)
            target_segment_offset = section0;

        SegmentTableEntry* base_segment = header->GetSegmentTableEntry(patch->unk);

        u32 patch_address = target_segment_offset + patch->GetSegmentOffset();
        u32 patch_address1 = target_segment->segment_offset + patch->GetSegmentOffset();

        ApplyPatch(patch, base_segment->segment_offset, patch_address, &patch_address1);
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
            auto export_ = loaded_exports.find("nnroAeabiAtexit_");
            if (export_ == loaded_exports.end())
                return;

            // Patch it!
            Patch* first_patch = reinterpret_cast<Patch*>(Memory::GetPointer(entry->symbol_offset));
            ApplyListPatches(header, first_patch, export_->second.cro_offset);
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
            auto export_ = loaded_exports.find(entry_name);
            if (export_ == loaded_exports.end())
                continue;

            u32 patch_base = export_->second.cro_offset;

            Patch* first_patch = reinterpret_cast<Patch*>(Memory::GetPointer(entry->symbol_offset));
            ApplyListPatches(header, first_patch, patch_base, relocated);
        }
    }
}

static u32 GetCROBaseByName(char* name) {
    for (u32 base : loaded_cros) {
        CROHeader* header = reinterpret_cast<CROHeader*>(Memory::GetPointer(base));
        char* cro_name = reinterpret_cast<char*>(Memory::GetPointer(header->name_offset));

        if (!strcmp(cro_name, name))
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
            ApplyListPatches(header, first_patch, target_base_segment->segment_offset + target_segment_offset, relocated);
        }

        // Apply the patches from the second table
        for (int j = 0; j < entry->table2_num; ++j) {
            Unk2TableEntry* table2_entry = entry->GetTable2Entry(j);
            u32 target_segment_id = table2_entry->offset_or_index & 0xF;
            u32 target_segment_offset = table2_entry->offset_or_index >> 4;
            SegmentTableEntry* target_base_segment = patch_cro->GetSegmentTableEntry(target_segment_id, true);

            Patch* first_patch = reinterpret_cast<Patch*>(Memory::GetPointer(table2_entry->patches_offset));
            ApplyListPatches(header, first_patch, target_base_segment->segment_offset + target_segment_offset, relocated);
        }
    }
}

static void LoadExportsTable(CROHeader* header, u32 base) {
    for (int i = 0; i < header->export_table_num; ++i) {
        ExportTableEntry* entry = header->GetExportTableEntry(i);
        SegmentTableEntry* target_segment = header->GetSegmentTableEntry(entry->GetTargetSegment());
        ExportedSymbol export_;
        export_.cro_base = base;
        export_.cro_offset = target_segment->segment_offset + entry->GetSegmentOffset();
        export_.name = reinterpret_cast<char*>(Memory::GetPointer(entry->name_offset));
        loaded_exports[export_.name] = export_;
    }
}

static u32 GetAddress(CROHeader* header, char* str) {
    if (header->export_tree_num) {
        ExportTreeEntry* first_entry = header->GetExportTreeEntry(0);
        u32 len = strlen(str);
        ExportTreeEntry* next_entry = header->GetExportTreeEntry(first_entry->unk);
        bool v16 = false;
        do {
            u16 v14 = 0;
            bool v12 = next_entry->GetSegmentOffset() >= len;
            if (v12 || !((*(str + next_entry->GetSegmentOffset()) >> next_entry->GetTargetSegment()) & 1))
                v14 = next_entry->unk;
            else
                v14 = next_entry->unk2;
            v16 = (v14 & 0x8000) == 0;
            next_entry = header->GetExportTreeEntry(v14 & 0x7FFF);
        } while (v16);

        u32 export_id = next_entry->export_table_id;
        ExportTableEntry* export_entry = header->GetExportTableEntry(export_id);
        char* export_name = (char*)Memory::GetPointer(export_entry->name_offset);
        if (!strcmp(export_name, str)) {
            SegmentTableEntry* segment = header->GetSegmentTableEntry(export_entry->GetTargetSegment());
            return segment->segment_offset + export_entry->GetSegmentOffset();
        }
    }
    return 0;
}

static void LinkCROs(CROHeader* new_cro, u32 base) {
    if (!loaded_cros.empty())
        new_cro->previous_cro = loaded_cros.back();

    if (new_cro->previous_cro) {
        CROHeader* previous_cro = reinterpret_cast<CROHeader*>(Memory::GetPointer(new_cro->previous_cro));
        previous_cro->next_cro = base;
    } else {
        new_cro->previous_cro = base;
    }
}

static void LoadCRO(u32 base, u8* cro, bool relocate_segments, u32 data_section0, u32 data_section1, bool crs) {
    CROHeader* header = reinterpret_cast<CROHeader*>(cro);

    u32 prev_section0 = 0;
    if (relocate_segments) {
        // Relocate segments
        header->RelocateSegmentsTable(base, data_section0, data_section1, prev_section0);
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
    ApplyRelocationPatches(header, base, prev_section0 + base);

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
        ApplyUnk2Patches(cro_header, cro_base, true);
    }

    // Relocate all offsets
    header->RelocateOffsets(base);

    if (!crs) {
        // Link the CROs
        LinkCROs(header, base);
    }

    loaded_cros.push_back(base);

    FileUtil::IOFile file(std::to_string(base) + ".cro", "wb+");
    file.WriteBytes(header, header->file_size);
    file.Close();
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
    u32 address        = cmd_buff[3];
    u32 value          = cmd_buff[4];
    u32 process        = cmd_buff[5];

    if (value != 0) {
        LOG_WARNING(Service_LDR, "This value should be zero, but is actually %u!", value);
    }

    loaded_exports.clear();
    loaded_cros.clear();

    std::shared_ptr<std::vector<u8>> cro = std::make_shared<std::vector<u8>>(crs_size);
    memcpy(cro->data(), crs_buffer_ptr, crs_size);

    // TODO(Subv): Check what the real hardware returns for MemoryState
    Kernel::g_current_process->vm_manager.MapMemoryBlock(address, cro, 0, crs_size, Kernel::MemoryState::Code);

    LoadCRO(address, Memory::GetPointer(address), false, 0, 0, true);

    cmd_buff[0] = IPC::MakeHeader(1, 1, 0);
    cmd_buff[1] = RESULT_SUCCESS.raw;

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
        LOG_WARNING(Service_LDR, "This value should be zero, but is actually %u!", value);
    }

    cmd_buff[0] = IPC::MakeHeader(2, 1, 0);
    cmd_buff[1] = RESULT_SUCCESS.raw;

    LOG_WARNING(Service_LDR, "(STUBBED) called. crs_buffer_ptr=0x%08X, crs_size=0x%08X, value=0x%08X, process=0x%08X",
                crs_buffer_ptr, crs_size, value, process);
}

static void LoadExeCRO(Service::Interface* self) {
    u32* cmd_buff = Kernel::GetCommandBuffer();
    u8* cro_buffer = Memory::GetPointer(cmd_buff[1]);
    u32 address = cmd_buff[2];
    u32 size = cmd_buff[3];

    std::shared_ptr<std::vector<u8>> cro = std::make_shared<std::vector<u8>>(size);
    memcpy(cro->data(), cro_buffer, size);

    // TODO(Subv): Check what the real hardware returns for MemoryState
    Kernel::g_current_process->vm_manager.MapMemoryBlock(address, cro, 0, size, Kernel::MemoryState::Code);

    LoadCRO(address, Memory::GetPointer(address), true, cmd_buff[4], cmd_buff[7], false);

    cmd_buff[0] = IPC::MakeHeader(4, 2, 0);
    cmd_buff[1] = RESULT_SUCCESS.raw;
    cmd_buff[2] = 0;
    LOG_WARNING(Service_LDR, "Loading CRO address=%08X", address);
}

static void UnloadCRO(Service::Interface* self) {
    u32* cmd_buff = Kernel::GetCommandBuffer();
    u32 address = cmd_buff[1];
    CROHeader* unload = reinterpret_cast<CROHeader*>(Memory::GetPointer(address));
    for (auto itr = loaded_cros.begin(); itr != loaded_cros.end(); ++itr) {
        if (*itr == address)
            continue;

        CROHeader* cro = reinterpret_cast<CROHeader*>(Memory::GetPointer(*itr));
        if (cro->next_cro == address) {
            cro->next_cro = unload->next_cro;
            if (unload->next_cro != 0) {
                CROHeader* next = reinterpret_cast<CROHeader*>(Memory::GetPointer(unload->next_cro));
                next->previous_cro = *itr;
            }
        }

        if (cro->previous_cro == address) {
            cro->previous_cro = unload->previous_cro;
            if (unload->previous_cro != 0) {
                CROHeader* prev = reinterpret_cast<CROHeader*>(Memory::GetPointer(unload->previous_cro));
                prev->next_cro = *itr;
            }
        }
    }

    loaded_cros.erase(std::remove(loaded_cros.begin(), loaded_cros.end(), address), loaded_cros.end());

    // TODO(Subv): Unload symbols and unmap memory

    cmd_buff[1] = RESULT_SUCCESS.raw;
    LOG_WARNING(Service_LDR, "Unloading CRO address=%08X", address);
}

const Interface::FunctionInfo FunctionTable[] = {
    {0x000100C2, Initialize,            "Initialize"},
    {0x00020082, LoadCRR,               "LoadCRR"},
    {0x00030042, nullptr,               "UnloadCCR"},
    {0x000402C2, LoadExeCRO,            "LoadExeCRO"},
    {0x000500C2, UnloadCRO,             "UnloadCRO"},
    {0x00060042, nullptr,               "CRO_Load?"},
    {0x00070042, nullptr,               "LoadCROSymbols"},
    {0x00080042, nullptr,               "Shutdown"},
    {0x000902C2, LoadExeCRO,            "LoadExeCRO_New?"},
};

////////////////////////////////////////////////////////////////////////////////////////////////////
// Interface class

Interface::Interface() {
    Register(FunctionTable);
}

} // namespace
