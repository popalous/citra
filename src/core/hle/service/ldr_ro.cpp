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
    u32 unk_size1;
    u32 always_zero;
    INSERT_PADDING_WORDS(0x4);
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
    u32 GetImportPatchesSegmentOffset() { return segment_offset >> 4; }

    SegmentTableEntry* GetSegmentTableEntry(u32 index);
    ResultCode RelocateSegmentsTable(u32 base, u32 size, u32 data_section0, u32 data_section1, u32& prev_data_section0);

    ExportTableEntry* GetExportTableEntry(u32 index);
    ResultCode RelocateExportsTable(u32 base);

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

    bool VerifyAndRelocateOffsets(u32 base, u32 size);
};

static std::unordered_map<std::string, ExportedSymbol> loaded_exports;
static std::vector<u32> loaded_cros;

SegmentTableEntry* CROHeader::GetSegmentTableEntry(u32 index) {
    return reinterpret_cast<SegmentTableEntry*>(Memory::GetPointer(segment_table_offset + sizeof(SegmentTableEntry) * index));
}

ResultCode CROHeader::RelocateSegmentsTable(u32 base, u32 size, u32 data_section0, u32 data_section1, u32& prev_data_section0) {
    u32 cro_end = base + size;

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
            if (entry->segment_offset > cro_end)
                return ResultCode(0xD9012C19);
        }
    }

    return RESULT_SUCCESS;
}

ExportTreeEntry* CROHeader::GetExportTreeEntry(u32 index) {
    return reinterpret_cast<ExportTreeEntry*>(Memory::GetPointer(export_tree_offset + sizeof(ExportTreeEntry) * index));
}

u32 CROHeader::GetUnk1TableEntry(u32 index) {
    return *reinterpret_cast<u32*>(Memory::GetPointer(unk1_offset + sizeof(u32) * index));
}

ExportTableEntry* CROHeader::GetExportTableEntry(u32 index) {
    return reinterpret_cast<ExportTableEntry*>(Memory::GetPointer(export_table_offset + sizeof(ExportTableEntry) * index));
}

ResultCode CROHeader::RelocateExportsTable(u32 base) {
    for (int i = 0; i < export_table_num; ++i) {
        ExportTableEntry* entry = GetExportTableEntry(i);
        if (entry->name_offset)
            entry->name_offset += base;

        if (entry->name_offset < export_strings_offset ||
            entry->name_offset > export_strings_offset + export_strings_num)
            return ResultCode(0xD9012C11);
    }

    return RESULT_SUCCESS;
}

Patch* CROHeader::GetImportPatch(u32 index) {
    return reinterpret_cast<Patch*>(Memory::GetPointer(import_patches_offset + sizeof(Patch) * index));
}

ImportTableEntry* CROHeader::GetImportTable1Entry(u32 index) {
    return reinterpret_cast<ImportTableEntry*>(Memory::GetPointer(import_table1_offset + sizeof(ImportTableEntry) * index));
}

ImportTableEntry* CROHeader::GetImportTable2Entry(u32 index) {
    return reinterpret_cast<ImportTableEntry*>(Memory::GetPointer(import_table2_offset + sizeof(ImportTableEntry) * index));
}

ImportTableEntry* CROHeader::GetImportTable3Entry(u32 index) {
    return reinterpret_cast<ImportTableEntry*>(Memory::GetPointer(import_table3_offset + sizeof(ImportTableEntry) * index));
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
    return reinterpret_cast<Unk3Patch*>(Memory::GetPointer(unk3_offset * sizeof(Unk3Patch) * index));
}

Patch* CROHeader::GetRelocationPatchEntry(u32 index) {
    return reinterpret_cast<Patch*>(Memory::GetPointer(relocation_patches_offset + sizeof(Patch) * index));
}

Unk2Patch* CROHeader::GetUnk2PatchEntry(u32 index) {
    return reinterpret_cast<Unk2Patch*>(Memory::GetPointer(unk2_offset + sizeof(Unk2Patch) * index));
}

bool CROHeader::VerifyAndRelocateOffsets(u32 base, u32 size) {
    u32 end = base + size;

    // Error if the magic is invalid
    if (strcmp(magic, "CRO0") != 0)
        return false;

    // If these values are set the game might be trying to load the same CRO multiple times
    if (next_cro || previous_cro)
        return false;

    // This seems to be a hard limit set by the RO module
    if (file_size >= 0x10000000 || unk_size1 >= 0x10000000)
        return false;

    if (always_zero != 0)
        return false;

    // Hard limit set by the RO module, it is unknown what the value means
    if (code_offset < 0x138)
        return false;

    if (module_name_offset < code_offset)
        return false;

    if (module_name_offset > segment_table_offset)
        return false;

    if (export_table_offset < segment_table_offset)
        return false;

    if (export_table_offset > export_tree_offset)
        return false;

    if (unk1_offset < export_tree_offset)
        return false;

    if (unk1_offset > export_strings_offset)
        return false;

    if (unk2_offset < export_strings_offset)
        return false;

    if (unk2_offset > import_patches_offset)
        return false;

    if (import_table1_offset < import_patches_offset)
        return false;

    if (import_table1_offset > import_table2_offset)
        return false;

    if (import_table3_offset < import_table2_offset)
        return false;

    if (import_table3_offset > import_strings_offset)
        return false;

    if (unk3_offset < import_strings_offset)
        return false;

    if (unk3_offset > relocation_patches_offset)
        return false;

    if (unk4_offset < relocation_patches_offset)
        return false;

    if (unk4_offset > unk_offset)
        return false;

    if (unk_offset > file_size)
        return false;

    if (name_offset) {
        name_offset += base;
        if (name_offset >= end)
            return false;
    }

    if (code_offset) {
        code_offset += base;
        if (code_offset >= end)
            return false;
    }

    if (unk_offset) {
        unk_offset += base;
        if (unk_offset >= end)
            return false;
    }

    if (module_name_offset) {
        module_name_offset += base;
        if (module_name_offset >= end)
            return false;
    }

    if (segment_table_offset) {
        segment_table_offset += base;
        if (segment_table_offset >= end)
            return false;
    }

    if (export_table_offset) {
        export_table_offset += base;
        if (export_table_offset >= end)
            return false;
    }

    if (unk1_offset) {
        unk1_offset += base;
        if (unk1_offset >= end)
            return false;
    }

    if (export_strings_offset) {
        export_strings_offset += base;
        if (export_strings_offset >= end)
            return false;
    }

    if (export_tree_offset) {
        export_tree_offset += base;
        if (export_tree_offset >= end)
            return false;
    }

    if (unk2_offset) {
        unk2_offset += base;
        if (unk2_offset >= end)
            return false;
    }

    if (import_patches_offset) {
        import_patches_offset += base;
        if (import_patches_offset >= end)
            return false;
    }

    if (import_table1_offset) {
        import_table1_offset += base;
        if (import_table1_offset >= end)
            return false;
    }

    if (import_table2_offset) {
        import_table2_offset += base;
        if (import_table2_offset >= end)
            return false;
    }

    if (import_table3_offset) {
        import_table3_offset += base;
        if (import_table3_offset >= end)
            return false;
    }

    if (import_strings_offset) {
        import_strings_offset += base;
        if (import_strings_offset >= end)
            return false;
    }

    if (unk3_offset) {
        unk3_offset += base;
        if (unk3_offset >= end)
            return false;
    }

    if (relocation_patches_offset) {
        relocation_patches_offset += base;
        if (relocation_patches_offset >= end)
            return false;
    }

    if (unk4_offset) {
        unk4_offset += base;
        if (unk4_offset >= end)
            return false;
    }

    if (code_offset + code_size > end ||
        unk_offset + unk_size > end ||
        module_name_offset + module_name_size > end ||
        segment_table_offset + sizeof(SegmentTableEntry) * segment_table_num > end ||
        export_table_offset + sizeof(ExportTableEntry) * export_table_num > end ||
        unk1_offset + sizeof(u32) * unk1_size > end ||
        export_strings_offset + export_strings_num > end ||
        export_tree_offset + sizeof(ExportTreeEntry) * export_tree_num > end ||
        unk2_offset + sizeof(Unk2Patch) * unk2_num > end ||
        import_patches_offset + sizeof(Patch) * import_patches_num ||
        import_table1_offset + sizeof(ImportTableEntry) * import_table1_num ||
        import_table2_offset + sizeof(ImportTableEntry) * import_table2_num ||
        import_table3_offset + sizeof(ImportTableEntry) * import_table3_num ||
        import_strings_offset + import_strings_num > end ||
        unk3_offset + sizeof(Unk3Patch) * unk3_num > end ||
        relocation_patches_offset + sizeof(Patch) * relocation_patches_num > end ||
        unk4_offset + 12 * unk4_num > end) {
            return false;
    }

    return true;
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
    u32 patch_base = 0;

    if (header->GetImportPatchesTargetSegment() < header->segment_table_num) {
        SegmentTableEntry* base_segment = header->GetSegmentTableEntry(header->GetImportPatchesTargetSegment());
        patch_base = base_segment->segment_offset + header->GetImportPatchesSegmentOffset();
    }

    u32 v10 = 1;
    for (int i = 0; i < header->import_patches_num; ++i) {
        Patch* patch = header->GetImportPatch(i);
        SegmentTableEntry* target_segment = header->GetSegmentTableEntry(patch->GetTargetSegment());
        ApplyPatch(patch, patch_base, target_segment->segment_offset + patch->GetSegmentOffset());
        if (v10)
            patch->unk2 = 0;
        v10 = patch->unk;
    }
}

static void ApplyListPatches(CROHeader* header, Patch* first_patch, u32 patch_base) {
    Patch* current_patch = first_patch;

    while (1) {
        SegmentTableEntry* target_segment = header->GetSegmentTableEntry(current_patch->GetTargetSegment());
        ApplyPatch(current_patch, patch_base, target_segment->segment_offset + current_patch->GetSegmentOffset());

        if (current_patch->unk)
            break;
        ++current_patch;
    }

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

static void ApplyImportTable1Patches(CROHeader* header, u32 base) {
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
            ApplyListPatches(header, first_patch, patch_base);
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

static void ApplyUnk2Patches(CROHeader* header, u32 base) {
    for (int i = 0; i < header->unk2_num; ++i) {
        Unk2Patch* entry = header->GetUnk2PatchEntry(i);
        u32 cro_base = GetCROBaseByName(reinterpret_cast<char*>(Memory::GetPointer(entry->string_offset)));
        if (cro_base == 0)
            continue;

        CROHeader* patch_cro = reinterpret_cast<CROHeader*>(Memory::GetPointer(cro_base));
        // Apply the patches from the first table
        for (int j = 0; j < entry->table1_num; ++j) {
            Unk2TableEntry* table1_entry = entry->GetTable1Entry(j);
            u32 unk1_table_entry = patch_cro->GetUnk1TableEntry(table1_entry->offset_or_index);
            u32 base_segment_id = unk1_table_entry & 0xF;
            u32 base_segment_offset = unk1_table_entry >> 4;
            SegmentTableEntry* base_segment = patch_cro->GetSegmentTableEntry(base_segment_id);

            Patch* first_patch = reinterpret_cast<Patch*>(Memory::GetPointer(base + table1_entry->patches_offset));
            ApplyListPatches(header, first_patch, base_segment->segment_offset + base_segment_offset);
        }

        // Apply the patches from the second table
        for (int j = 0; j < entry->table2_num; ++j) {
            Unk2TableEntry* table2_entry = entry->GetTable2Entry(j);
            u32 base_segment_id = table2_entry->offset_or_index & 0xF;
            u32 base_segment_offset = table2_entry->offset_or_index >> 4;
            SegmentTableEntry* base_segment = patch_cro->GetSegmentTableEntry(base_segment_id);

            Patch* first_patch = reinterpret_cast<Patch*>(Memory::GetPointer(table2_entry->patches_offset));
            ApplyListPatches(header, first_patch, base_segment->segment_offset + base_segment_offset);
        }
    }
}

static void BackApplyUnk2Patches(CROHeader* header, u32 base, CROHeader* new_header, u32 new_base) {
    for (int i = 0; i < header->unk2_num; ++i) {
        Unk2Patch* entry = header->GetUnk2PatchEntry(i);
        char* old_cro_name = reinterpret_cast<char*>(Memory::GetPointer(entry->string_offset));
        char* new_cro_name = reinterpret_cast<char*>(Memory::GetPointer(new_base + new_header->name_offset));
        if (strcmp(old_cro_name, new_cro_name) != 0)
            continue;

        CROHeader* patch_cro = new_header;

        // Apply the patches from the first table
        for (int j = 0; j < entry->table1_num; ++j) {
            Unk2TableEntry* table1_entry = entry->GetTable1Entry(j);
            u32 unk1_table_entry = patch_cro->GetUnk1TableEntry(table1_entry->offset_or_index);
            u32 base_segment_id = unk1_table_entry & 0xF;
            u32 base_segment_offset = unk1_table_entry >> 4;
            SegmentTableEntry* base_segment = patch_cro->GetSegmentTableEntry(base_segment_id);

            Patch* first_patch = reinterpret_cast<Patch*>(Memory::GetPointer(base + table1_entry->patches_offset));
            ApplyListPatches(header, first_patch, base_segment->segment_offset + base_segment_offset);
        }

        // Apply the patches from the second table
        for (int j = 0; j < entry->table2_num; ++j) {
            Unk2TableEntry* table2_entry = entry->GetTable2Entry(j);
            u32 base_segment_id = table2_entry->offset_or_index & 0xF;
            u32 base_segment_offset = table2_entry->offset_or_index >> 4;
            SegmentTableEntry* base_segment = patch_cro->GetSegmentTableEntry(base_segment_id);

            Patch* first_patch = reinterpret_cast<Patch*>(Memory::GetPointer(table2_entry->patches_offset));
            ApplyListPatches(header, first_patch, base_segment->segment_offset + base_segment_offset);
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

static ResultCode LoadCRO(u32 base, u32 size, u8* cro, u32 data_section0, u32 data_section1, bool crs) {
    CROHeader* header = reinterpret_cast<CROHeader*>(cro);

    // Relocate all offsets
    if (!header->VerifyAndRelocateOffsets(base, size))
        return ResultCode(0xD9012C11);

    if (header->module_name_size &&
        Memory::Read8(header->module_name_offset + header->module_name_size - 1) != 0) {
        // The module name must end with '\0'
        return ResultCode(0xD9012C0B);
    }

    u32 prev_section0 = 0;
    ResultCode result = RESULT_SUCCESS;

    if (!crs) {
        // Relocate segments
        result = header->RelocateSegmentsTable(base, size, data_section0, data_section1, prev_section0);
        if (result.IsError())
            return result;
    }

    // Rebase export table
    result = header->RelocateExportsTable(base);

    if (result.IsError())
        return result;

    if (header->export_strings_num &&
        Memory::Read8(header->export_strings_offset + header->export_strings_num - 1) != 0)
        return ResultCode(0xD9012C0B);

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
    ApplyImportTable1Patches(header, base);

    // Apply unk2 patches
    ApplyUnk2Patches(header, base);

    // Load exports
    LoadExportsTable(header, base);

    // Retroactively apply import table 1 patches to the previous CROs
    // Retroactively apply unk2 patches to the previous CROs
    for (auto itr = loaded_cros.rbegin(); itr != loaded_cros.rend(); ++itr) {
        u32 cro_base = *itr;
        CROHeader* cro_header = reinterpret_cast<CROHeader*>(Memory::GetPointer(cro_base));
        ApplyImportTable1Patches(cro_header, cro_base);
        BackApplyUnk2Patches(cro_header, cro_base, header, base);
    }

    // Link the CROs
    LinkCROs(header, base);

    loaded_cros.push_back(base);

    memcpy(header->magic, "FIXD", 4);

    LOG_WARNING(Service_LDR, "Loaded CRO name %s", reinterpret_cast<char*>(Memory::GetPointer(header->name_offset)));

    FileUtil::IOFile file(std::to_string(base) + ".cro", "wb+");
    file.WriteBytes(header, header->file_size);
    file.Close();

    return RESULT_SUCCESS;
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

    cmd_buff[0] = IPC::MakeHeader(1, 1, 0);
    cmd_buff[1] = LoadCRO(address, crs_size, Memory::GetPointer(address), 0, 0, true).raw;

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

    cmd_buff[0] = IPC::MakeHeader(4, 2, 0);
    cmd_buff[1] = LoadCRO(address, size, Memory::GetPointer(address), cmd_buff[4], cmd_buff[7], false).raw;
    cmd_buff[2] = 0;

    LOG_WARNING(Service_LDR, "Loading CRO address=%08X", address);
}

static void UnloadCRO(Service::Interface* self) {
    u32* cmd_buff = Kernel::GetCommandBuffer();
    u32 address = cmd_buff[1];
    CROHeader* unload = reinterpret_cast<CROHeader*>(Memory::GetPointer(address));
    u32 size = unload->file_size;
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

    std::memset(Memory::GetPointer(address), 0, size);
    Kernel::g_current_process->vm_manager.UnmapRange(address, size);

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
