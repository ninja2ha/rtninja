// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#ifndef RTNINJA_RTNINJA_CORE_INTERNAL_PE_IMAGE_H_
#define RTNINJA_RTNINJA_CORE_INTERNAL_PE_IMAGE_H_

#include "rtninja-core/internal/window_types.h"

namespace rtninja {

//
// This class is a wrapper for the Portable Executable File Format (PE).
// Its main purpose is to provide an easy way to work with imports and exports
// from a file, mapped in memory as image.
//
class PEImage {
 public:
  // Callback to enumerate exports.
  // |function| is the actual address of the symbol. If |forward| is not null, 
  // it contains the dll and symbol to forward this export to. cookie is the 
  // value passed to the enumerate method.
  // Returns true to continue the enumeration.
  using EnumExportsFunction =
      bool (*)(const PEImage& pe_image, DWORD ordinal, DWORD hint, 
               LPCSTR name, PVOID function,
               LPCSTR forward, PVOID cookie);

  explicit PEImage(HMODULE module) : module_(module) { }
  explicit PEImage(const void* module) : 
      module_(reinterpret_cast<HMODULE>(const_cast<void*>(module))) {}
  ~PEImage() = default;

  // Gets the HMODULE for this object.
  HMODULE module() const;

  // Checks if this symbol is actually an ordinal.
  static bool IsOrdinal(LPCSTR function_name);

  // Converts a named symbol to the corresponding ordinal.
  static WORD ToOrdinal(LPCSTR function_name);

  // Returns the DOS_HEADER for this PE.
  PIMAGE_DOS_HEADER GetDosHeader() const;

  // Returns the NT_HEADER for this PE.
  PIMAGE_NT_HEADERS GetNTHeaders() const;

  enum ImageType {
    kImageTypeUnknow,
    kImageType32,
    kImageType64
  };
  // Returns the ImageType for this PE.
  int GetImageType() const;

  // Returns number of sections of this PE.
  WORD GetNumSections() const;

  // Returns the header for a given section.
  // returns NULL if there is no such section.
  PIMAGE_SECTION_HEADER GetSectionHeader(UINT section) const;

  // Returns the section header for a given address.
  // Use: s = image.GetImageSectionFromAddr(a);
  // Post: 's' is the section header of the section that contains 'a'
  //       or NULL if there is no such section.
  PIMAGE_SECTION_HEADER GetImageSectionFromAddr(PVOID address) const;

  // Returns the section header for a given section.
  PIMAGE_SECTION_HEADER GetImageSectionHeaderByName(LPCSTR section_name) const;

  // Converts an rva value to the appropriate address.
  virtual PVOID RVAToAddr(uintptr_t rva) const;

  // Converts an rva value to an offset on disk.
  // Returns true on success.
  bool ImageRVAToOnDiskOffset(uintptr_t rva, DWORD* on_disk_offset) const;

  // Converts an address to an offset on disk.
  // Returns true on success.
  bool ImageAddrToOnDiskOffset(LPVOID address, DWORD* on_disk_offset) const;

  // Retrieves the contents of the image's CodeView debug entry, returning true
  // if such an entry is found and is within a section mapped into the current
  // process's memory. |guid|, |age|, and |pdb_filename| are each optional and
  // may be NULL. |pdb_filename_length| is mandatory if |pdb_filename| is not
  // NULL, as the latter is populated with a direct reference to a string in the
  // image that is is not guaranteed to be terminated (note: informal
  // documentation indicates that it should be terminated, but the data is
  // untrusted). Furthermore, owing to its nature of being a string in the
  // image, it is only valid while the image is mapped into the process, and the
  // caller is not responsible for freeing it. |pdb_filename_length| is
  // populated with the string length of |pdb_filename| (not including a
  // terminator) and must be used rather than relying on |pdb_filename| being
  // properly terminated.
  bool GetDebugId(LPGUID guid,                /* out */
                  LPDWORD age,                /* out */
                  LPCSTR* pdb_filename,       /* out */
                  size_t* pdb_filename_length /* out */) const;

  // Returns a given export entry.
  // Use: e = image.GetProcExportEntry(f);
  // Pre: 'f' is either a zero terminated string or ordinal
  // Post: 'e' is a pointer to the export directory entry
  //       that contains 'f's export RVA, or NULL if 'f'
  //       is not exported from this image
  PDWORD GetProcExportEntry(LPCSTR function_name) const;

  // Returns the address for a given exported symbol.
  // Use: p = image.GetProcAddress(f, is_forwarded);
  // Pre: 'f' is either a zero terminated string or ordinal.
  // Post: if 'f' is a non-forwarded export from image, 'p' is
  //       the exported function. If 'f' is a forwarded export
  //       then 'is_forwarded' is set as true, otherwise false.
  FARPROC GetProcAddress(LPCSTR function_name, bool* is_forwarded) const;

  // Retrieves the ordinal for a given exported symbol.
  // Returns true if the symbol was found.
  bool GetProcOrdinal(LPCSTR function_name, WORD* ordinal) const;

  // Returns the exports directory.
  PIMAGE_EXPORT_DIRECTORY GetExportDirectory() const;

  // Enumerates PE exports.
  // cookie is a generic cookie to pass to the callback.
  // Returns true on success.
  bool EnumExports(EnumExportsFunction callback, PVOID cookie) const;

 private:
  // Returns a pointer to a data directory, or NULL if |directory| is out of
  // range.
  const IMAGE_DATA_DIRECTORY* GetDataDirectory(UINT directory) const;

  // Returns the address of a given directory entry or NULL if |directory| is
  // out of bounds.
  PVOID GetImageDirectoryEntryAddr(UINT directory) const;

  // Returns the size of a given directory entry or 0 if |directory| is out of
  // bounds.
  DWORD GetImageDirectoryEntrySize(UINT directory) const;

  HMODULE module_ = nullptr;
};

// This class is an extension to the PEImage class that allows working with PE
// files mapped as data instead of as image file.
class PEImageAsData : public PEImage {
public:
  explicit PEImageAsData(HMODULE hModule) : PEImage(hModule) { }

  PVOID RVAToAddr(uintptr_t rva) const override;
};

}  // namespace rtninja

#endif  // RTNINJA_RTNINJA_CORE_INTERNAL_PE_IMAGE_H_