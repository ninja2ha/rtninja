// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.
#include "rtninja-core/internal/pe_image.h"

namespace rtninja {

namespace {

// PdbInfo Signature
const DWORD kPdbInfoSignature = 'SDSR';

struct PdbInfo {
  DWORD Signature;
  GUID Guid;
  DWORD Age;
  char PdbFileName[1];
};

// Compare two strings byte by byte on an unsigned basis.
//   if s1 == s2, return 0
//   if s1 < s2, return negative
//   if s1 > s2, return positive
// Exception if inputs are invalid.
int StrCmpByByte(LPCSTR s1, LPCSTR s2) {
  while (*s1 != '\0' && *s1 == *s2) {
    ++s1;
    ++s2;
  }

  return (*reinterpret_cast<const unsigned char*>(s1) -
          *reinterpret_cast<const unsigned char*>(s2));
}

}  // namespace

HMODULE PEImage::module() const {
  return module_;
}

bool PEImage::IsOrdinal(LPCSTR function_name) {
  return reinterpret_cast<uintptr_t>(function_name) <= 0xFFFF;
}

WORD PEImage::ToOrdinal(LPCSTR function_name) {
  return static_cast<WORD>(reinterpret_cast<intptr_t>(function_name));
}

PIMAGE_DOS_HEADER PEImage::GetDosHeader() const {
  return reinterpret_cast<PIMAGE_DOS_HEADER>(module());
}

PIMAGE_NT_HEADERS PEImage::GetNTHeaders() const {
  PIMAGE_DOS_HEADER dos_header = GetDosHeader();

  return reinterpret_cast<PIMAGE_NT_HEADERS>(
      reinterpret_cast<char*>(dos_header) + dos_header->e_lfanew);
}

int PEImage::GetImageType() const {
  PIMAGE_NT_HEADERS nt_headers = GetNTHeaders();
  WORD magic = nt_headers ? nt_headers->OptionalHeader.Magic : 0;
  switch (magic) {
  case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
    return kImageType32;
  case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
    return kImageType64;
  default:
    return kImageTypeUnknow;
  }
}

WORD PEImage::GetNumSections() const {
  return GetNTHeaders()->FileHeader.NumberOfSections;
}

PIMAGE_SECTION_HEADER PEImage::GetSectionHeader(UINT section) const {
  PIMAGE_NT_HEADERS nt_headers = GetNTHeaders();
  PIMAGE_SECTION_HEADER first_section = IMAGE_FIRST_SECTION(nt_headers);

  if (section < nt_headers->FileHeader.NumberOfSections)
    return first_section + section;
  else
    return nullptr;
}

PIMAGE_SECTION_HEADER PEImage::GetImageSectionFromAddr(PVOID address) const {
  PBYTE target = reinterpret_cast<PBYTE>(address);
  PIMAGE_SECTION_HEADER section;

  for (UINT i = 0; nullptr != (section = GetSectionHeader(i)); i++) {
    // Don't use the virtual RVAToAddr.
    PBYTE start =
        reinterpret_cast<PBYTE>(PEImage::RVAToAddr(section->VirtualAddress));

    DWORD size = section->Misc.VirtualSize;

    if ((start <= target) && (start + size > target))
      return section;
  }

  return nullptr;
}

PIMAGE_SECTION_HEADER PEImage::GetImageSectionHeaderByName(
    LPCSTR section_name) const {
  if (nullptr == section_name)
    return nullptr;

  PIMAGE_SECTION_HEADER ret = nullptr;
  int num_sections = GetNumSections();

  for (int i = 0; i < num_sections; i++) {
    PIMAGE_SECTION_HEADER section = GetSectionHeader(i);
    if (_strnicmp(reinterpret_cast<LPCSTR>(section->Name), section_name,
                  sizeof(section->Name)) == 0) {
      ret = section;
      break;
    }
  }

  return ret;
}

PVOID PEImage::RVAToAddr(uintptr_t rva) const {
  if (module() == nullptr || rva == 0)
    return nullptr;

  return reinterpret_cast<BYTE*>(module()) + rva;
}

bool PEImage::ImageRVAToOnDiskOffset(uintptr_t rva,
                                     DWORD* on_disk_offset) const {
  LPVOID address = RVAToAddr(rva);
  return ImageAddrToOnDiskOffset(address, on_disk_offset);
}

bool PEImage::ImageAddrToOnDiskOffset(LPVOID address,
                                      DWORD* on_disk_offset) const {
  if (nullptr == address)
    return false;

  // Get the section that this address belongs to.
  PIMAGE_SECTION_HEADER section_header = GetImageSectionFromAddr(address);
  if (nullptr == section_header)
    return false;

  // Don't follow the virtual RVAToAddr, use the one on the base.
  DWORD offset_within_section =
      static_cast<DWORD>(reinterpret_cast<uintptr_t>(address)) -
      static_cast<DWORD>(reinterpret_cast<uintptr_t>(
          PEImage::RVAToAddr(section_header->VirtualAddress)));

  *on_disk_offset = section_header->PointerToRawData + offset_within_section;
  return true;
}

bool PEImage::GetDebugId(LPGUID guid,
                         LPDWORD age,
                         LPCSTR* pdb_filename,
                         size_t* pdb_filename_length) const {
  DWORD debug_directory_size =
      GetImageDirectoryEntrySize(IMAGE_DIRECTORY_ENTRY_DEBUG);
  PIMAGE_DEBUG_DIRECTORY debug_directory =
      reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(
          GetImageDirectoryEntryAddr(IMAGE_DIRECTORY_ENTRY_DEBUG));
  if (!debug_directory)
    return false;

  size_t directory_count = debug_directory_size / sizeof(IMAGE_DEBUG_DIRECTORY);
  for (size_t index = 0; index < directory_count; ++index) {
    const IMAGE_DEBUG_DIRECTORY& entry = debug_directory[index];
    if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW)
      continue;  // Unsupported debugging info format.
    if (entry.SizeOfData < sizeof(PdbInfo))
      continue;  // The data is too small to hold PDB info.
    const PdbInfo* pdb_info =
        reinterpret_cast<const PdbInfo*>(RVAToAddr(entry.AddressOfRawData));
    if (!pdb_info)
      continue;  // The data is not present in a mapped section.
    if (pdb_info->Signature != kPdbInfoSignature)
      continue;  // Unsupported PdbInfo signature

    if (guid)
      *guid = pdb_info->Guid;
    if (age)
      *age = pdb_info->Age;
    if (pdb_filename) {
      const size_t length_max =
          entry.SizeOfData - FIELD_OFFSET(PdbInfo, PdbFileName);
      const char* eos = pdb_info->PdbFileName;
      for (const char* const end = pdb_info->PdbFileName + length_max;
           eos < end && *eos; ++eos)
        ;
      *pdb_filename_length = eos - pdb_info->PdbFileName;
      *pdb_filename = pdb_info->PdbFileName;
    }
    return true;
  }
  return false;
}

PDWORD PEImage::GetProcExportEntry(LPCSTR function_name) const {
  PIMAGE_EXPORT_DIRECTORY exports = GetExportDirectory();
  if (nullptr == exports)
    return nullptr;

  WORD ordinal = 0;
  if (!GetProcOrdinal(function_name, &ordinal))
    return nullptr;

  PDWORD functions =
      reinterpret_cast<PDWORD>(RVAToAddr(exports->AddressOfFunctions));

  return functions + ordinal - exports->Base;
}

FARPROC PEImage::GetProcAddress(LPCSTR function_name, 
                                bool* is_forwarded) const {
  PDWORD export_entry = GetProcExportEntry(function_name);
  if (nullptr == export_entry)
    return nullptr;

  PBYTE function = reinterpret_cast<PBYTE>(RVAToAddr(*export_entry));

  PBYTE exports = reinterpret_cast<PBYTE>(
      GetImageDirectoryEntryAddr(IMAGE_DIRECTORY_ENTRY_EXPORT));
  DWORD size = GetImageDirectoryEntrySize(IMAGE_DIRECTORY_ENTRY_EXPORT);
  if (!exports || !size)
    return nullptr;

  // Check for forwarded exports as a special case.
  if (is_forwarded) 
    *is_forwarded = (function >= exports && function < (exports + size));
  
  return reinterpret_cast<FARPROC>(function);
}

bool PEImage::GetProcOrdinal(LPCSTR function_name, WORD* ordinal) const {
  if (nullptr == ordinal)
    return false;

  PIMAGE_EXPORT_DIRECTORY exports = GetExportDirectory();

  if (nullptr == exports)
    return false;

  if (IsOrdinal(function_name)) {
    *ordinal = ToOrdinal(function_name);
  } else {
    PDWORD names = reinterpret_cast<PDWORD>(RVAToAddr(exports->AddressOfNames));
    PDWORD lower = names;
    PDWORD upper = names + exports->NumberOfNames;
    int cmp = -1;

    // Binary Search for the name.
    while (lower != upper) {
      PDWORD middle = lower + (upper - lower) / 2;
      LPCSTR name = reinterpret_cast<LPCSTR>(RVAToAddr(*middle));

      // This may be called by sandbox before MSVCRT dll loads, so can't use
      // CRT function here.
      cmp = StrCmpByByte(function_name, name);

      if (cmp == 0) {
        lower = middle;
        break;
      }

      if (cmp > 0)
        lower = middle + 1;
      else
        upper = middle;
    }

    if (cmp != 0)
      return false;

    PWORD ordinals =
        reinterpret_cast<PWORD>(RVAToAddr(exports->AddressOfNameOrdinals));

    *ordinal = ordinals[lower - names] + static_cast<WORD>(exports->Base);
  }
  return true;
}

PIMAGE_EXPORT_DIRECTORY PEImage::GetExportDirectory() const {
  return reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
      GetImageDirectoryEntryAddr(IMAGE_DIRECTORY_ENTRY_EXPORT));
}

bool PEImage::EnumExports(EnumExportsFunction callback, PVOID cookie) const {
  PVOID directory = GetImageDirectoryEntryAddr(IMAGE_DIRECTORY_ENTRY_EXPORT);
  DWORD size = GetImageDirectoryEntrySize(IMAGE_DIRECTORY_ENTRY_EXPORT);

  // Check if there are any exports at all.
  if (!directory || !size)
    return true;

  PIMAGE_EXPORT_DIRECTORY exports =
      reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(directory);
  UINT ordinal_base = exports->Base;
  UINT num_funcs = exports->NumberOfFunctions;
  UINT num_names = exports->NumberOfNames;
  PDWORD functions =
      reinterpret_cast<PDWORD>(RVAToAddr(exports->AddressOfFunctions));
  PDWORD names = reinterpret_cast<PDWORD>(RVAToAddr(exports->AddressOfNames));
  PWORD ordinals =
      reinterpret_cast<PWORD>(RVAToAddr(exports->AddressOfNameOrdinals));

  for (UINT count = 0; count < num_funcs; count++) {
    PVOID func = RVAToAddr(functions[count]);
    if (nullptr == func)
      continue;

    // Check for a name.
    LPCSTR name = nullptr;
    UINT hint;
    for (hint = 0; hint < num_names; hint++) {
      if (ordinals[hint] == count) {
        name = reinterpret_cast<LPCSTR>(RVAToAddr(names[hint]));
        break;
      }
    }

    if (name == nullptr)
      hint = 0;

    // Check for forwarded exports.
    LPCSTR forward = nullptr;
    if (reinterpret_cast<char*>(func) >= reinterpret_cast<char*>(directory) &&
        reinterpret_cast<char*>(func) <=
            reinterpret_cast<char*>(directory) + size) {
      forward = reinterpret_cast<LPCSTR>(func);
      func = nullptr;
    }

    if (!callback(*this, ordinal_base + count, hint, name, func, forward,
                  cookie))
      return false;
  }

  return true;
}

const IMAGE_DATA_DIRECTORY* PEImage::GetDataDirectory(UINT directory) const {
  PIMAGE_NT_HEADERS nt_headers = GetNTHeaders();
  WORD magic = nt_headers ? nt_headers->OptionalHeader.Magic : 0;

  if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    PIMAGE_OPTIONAL_HEADER32 opt_header = 
        reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(&nt_headers->OptionalHeader);
    if (directory >= opt_header->NumberOfRvaAndSizes)
      return nullptr;

    // Is there space for this directory entry in the optional header?
    if (nt_headers->FileHeader.SizeOfOptionalHeader <
        (FIELD_OFFSET(IMAGE_OPTIONAL_HEADER, DataDirectory) +
         (directory + 1) * sizeof(IMAGE_DATA_DIRECTORY))) {
      return nullptr;
    }

    return &nt_headers->OptionalHeader.DataDirectory[directory];
  }
   
  else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    PIMAGE_OPTIONAL_HEADER64 opt_header = 
        reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&nt_headers->OptionalHeader);
    if (directory >= opt_header->NumberOfRvaAndSizes)
      return nullptr;

    // Is there space for this directory entry in the optional header?
    if (nt_headers->FileHeader.SizeOfOptionalHeader <
        (FIELD_OFFSET(IMAGE_OPTIONAL_HEADER, DataDirectory) +
         (directory + 1) * sizeof(IMAGE_DATA_DIRECTORY))) {
      return nullptr;
    }

    return &nt_headers->OptionalHeader.DataDirectory[directory];
  }

  return nullptr;
}

PVOID PEImage::GetImageDirectoryEntryAddr(UINT directory) const {
  const IMAGE_DATA_DIRECTORY* const entry = GetDataDirectory(directory);
  return entry ? RVAToAddr(entry->VirtualAddress) : nullptr;
}

DWORD PEImage::GetImageDirectoryEntrySize(UINT directory) const {
  const IMAGE_DATA_DIRECTORY* const entry = GetDataDirectory(directory);
  return entry ? entry->Size : 0;
}

PVOID PEImageAsData::RVAToAddr(uintptr_t rva) const {
  if (rva == 0)
    return nullptr;

  PVOID in_memory = PEImage::RVAToAddr(rva);
  DWORD disk_offset;

  if (!ImageAddrToOnDiskOffset(in_memory, &disk_offset))
    return nullptr;

  return PEImage::RVAToAddr(disk_offset);
}

}  // namespace rtninja