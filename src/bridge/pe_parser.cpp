// ============================================================================
// PhantomScope — pe_parser.cpp
// Windows PE (Portable Executable) Binary Parser
//
// Manually parses PE headers without relying on dbghelp.dll or imagehlp.dll,
// giving us full control and avoiding API hooks placed by AV/EDR products.
//
// Extracts:
//   - Import Address Table (IAT): all imported DLL names
//   - Section table: name, sizes, entropy, permissions
//   - Optional header metadata: timestamp, machine type, subsystem
//   - .NET CLR header detection (IsDotNet)
//   - Debug directory presence (HasDebugDirectory)
//
// Uses memory-mapped file I/O for zero-copy parsing of large binaries.
// ============================================================================

#include "pe_parser.h"
#include "asm_bridge.h"

#include <cstring>
#include <cstdio>
#include <algorithm>
#include <stdexcept>

#ifdef _WIN32
  #include <windows.h>
#else
  // Cross-compile stubs for building on Linux for analysis purposes
  #define IMAGE_DOS_SIGNATURE   0x5A4D
  #define IMAGE_NT_SIGNATURE    0x00004550
  #define IMAGE_FILE_MACHINE_AMD64 0x8664

  #pragma pack(push, 1)
  struct IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    uint16_t e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid, e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
  };

  struct IMAGE_FILE_HEADER {
    uint16_t Machine, NumberOfSections;
    uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    uint16_t SizeOfOptionalHeader, Characteristics;
  };

  struct IMAGE_DATA_DIRECTORY { uint32_t VirtualAddress, Size; };

  struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint, BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    uint16_t MajorImageVersion, MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint64_t SizeOfStackReserve, SizeOfStackCommit;
    uint64_t SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
  };

  struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint, BaseOfCode, BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    uint16_t MajorImageVersion, MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint32_t SizeOfStackReserve, SizeOfStackCommit;
    uint32_t SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
  };

  struct IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
  };

  struct IMAGE_NT_HEADERS32 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
  };

  struct IMAGE_SECTION_HEADER {
    uint8_t  Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations, PointerToLinenumbers;
    uint16_t NumberOfRelocations, NumberOfLinenumbers;
    uint32_t Characteristics;
  };

  struct IMAGE_IMPORT_DESCRIPTOR {
    uint32_t OriginalFirstThunk, TimeDateStamp, ForwarderChain;
    uint32_t Name, FirstThunk;
  };

  #define IMAGE_DIRECTORY_ENTRY_IMPORT  1
  #define IMAGE_DIRECTORY_ENTRY_DEBUG   6
  #define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14
  #define IMAGE_SCN_MEM_EXECUTE  0x20000000
  #define IMAGE_SCN_MEM_WRITE    0x80000000
  #define PE32_MAGIC  0x010B
  #define PE64_MAGIC  0x020B
  #pragma pack(pop)
#endif

namespace PhantomScope {

// ============================================================================
// RVA → File offset conversion
// ============================================================================
static uint32_t RvaToOffset(
    uint32_t rva,
    const IMAGE_SECTION_HEADER* sections,
    uint16_t num_sections)
{
    for (uint16_t i = 0; i < num_sections; ++i) {
        uint32_t sec_start = sections[i].VirtualAddress;
        uint32_t sec_end   = sec_start + sections[i].VirtualSize;
        if (rva >= sec_start && rva < sec_end) {
            return sections[i].PointerToRawData + (rva - sec_start);
        }
    }
    return 0;
}

// ============================================================================
// PEParser — Constructor
// ============================================================================
PEParser::PEParser(const std::string& path)
    : path_(path) {}

// ============================================================================
// PEParser::Parse
// Reads the file via memory mapping and extracts all relevant metadata
// ============================================================================
bool PEParser::Parse() {
    if (parsed_) return true;

    const uint8_t* base  = nullptr;
    uint64_t file_size   = 0;

#ifdef _WIN32
    HANDLE hFile = CreateFileA(
        path_.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER li;
    GetFileSizeEx(hFile, &li);
    file_size = static_cast<uint64_t>(li.QuadPart);

    if (file_size < sizeof(IMAGE_DOS_HEADER) + 4) {
        CloseHandle(hFile);
        return false;
    }

    HANDLE hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) { CloseHandle(hFile); return false; }

    base = static_cast<const uint8_t*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!base) { CloseHandle(hMap); CloseHandle(hFile); return false; }
#else
    // Linux: open and mmap
    int fd = open(path_.c_str(), O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    fstat(fd, &st);
    file_size = static_cast<uint64_t>(st.st_size);

    if (file_size < sizeof(IMAGE_DOS_HEADER) + 4) { close(fd); return false; }

    void* mptr = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mptr == MAP_FAILED) return false;
    base = static_cast<const uint8_t*>(mptr);
#endif

    bool result = ParseFromMemory(base, file_size);

#ifdef _WIN32
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
#else
    munmap(const_cast<uint8_t*>(base), file_size);
#endif

    parsed_ = result;
    return result;
}

bool PEParser::ParseFromMemory(const uint8_t* base, uint64_t size) {
    // Validate DOS header
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    uint32_t pe_offset = static_cast<uint32_t>(dos->e_lfanew);
    if (pe_offset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) > size) return false;

    const uint32_t* signature = reinterpret_cast<const uint32_t*>(base + pe_offset);
    if (*signature != IMAGE_NT_SIGNATURE) return false;

    const auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + pe_offset);
    const auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + pe_offset);

    uint16_t opt_magic = nt32->OptionalHeader.Magic;
    is64_ = (opt_magic == PE64_MAGIC);

    if (opt_magic != PE32_MAGIC && opt_magic != PE64_MAGIC) return false;

    const IMAGE_FILE_HEADER* fhdr = &nt32->FileHeader;
    timestamp_ = static_cast<uint64_t>(fhdr->TimeDateStamp);

    uint16_t num_sections = fhdr->NumberOfSections;
    uint16_t opt_size     = fhdr->SizeOfOptionalHeader;

    // Section headers follow the optional header
    uint32_t sections_offset = pe_offset + 4 + sizeof(IMAGE_FILE_HEADER) + opt_size;
    if (sections_offset + num_sections * sizeof(IMAGE_SECTION_HEADER) > size) return false;

    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        base + sections_offset);

    // Data directory pointers
    const IMAGE_DATA_DIRECTORY* data_dirs  = nullptr;
    uint32_t                     num_dirs   = 0;

    if (is64_) {
        data_dirs = nt64->OptionalHeader.DataDirectory;
        num_dirs  = nt64->OptionalHeader.NumberOfRvaAndSizes;
    } else {
        data_dirs = nt32->OptionalHeader.DataDirectory;
        num_dirs  = nt32->OptionalHeader.NumberOfRvaAndSizes;
    }

    // ---- Import table ----
    if (num_dirs > IMAGE_DIRECTORY_ENTRY_IMPORT) {
        uint32_t import_rva = data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        uint32_t import_off = import_rva ? RvaToOffset(import_rva, sections, num_sections) : 0;

        if (import_off && import_off + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= size) {
            const auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
                base + import_off);

            while (desc->Name != 0) {
                uint32_t name_off = RvaToOffset(desc->Name, sections, num_sections);
                if (name_off && name_off < size) {
                    std::string dll_name(
                        reinterpret_cast<const char*>(base + name_off));
                    // Normalize to lowercase
                    std::transform(dll_name.begin(), dll_name.end(),
                                   dll_name.begin(), ::tolower);
                    imports_.push_back(dll_name);
                }
                ++desc;
                // Bounds check
                if (reinterpret_cast<const uint8_t*>(desc + 1) > base + size) break;
            }
        }
    }

    // ---- Debug directory ----
    if (num_dirs > IMAGE_DIRECTORY_ENTRY_DEBUG) {
        hasdebug_ = data_dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress != 0;
    }

    // ---- .NET CLR header (COM descriptor) ----
    if (num_dirs > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
        isdotnet_ = data_dirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0;
    }

    // ---- Section table with entropy ----
    for (uint16_t i = 0; i < num_sections; ++i) {
        const auto& sec = sections[i];

        SectionInfo info;
        // Section name is 8 bytes, may not be null-terminated
        info.name = std::string(reinterpret_cast<const char*>(sec.Name),
                                strnlen(reinterpret_cast<const char*>(sec.Name), 8));

        info.virtual_size   = sec.VirtualSize;
        info.raw_size       = sec.SizeOfRawData;
        info.is_executable  = (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        info.is_writable    = (sec.Characteristics & IMAGE_SCN_MEM_WRITE)   != 0;
        info.entropy        = 0.0;

        // Compute entropy for this section
        if (sec.PointerToRawData && sec.SizeOfRawData &&
            sec.PointerToRawData + sec.SizeOfRawData <= size)
        {
            double ent = 0.0;
            AsmEntropyCalc(base + sec.PointerToRawData, sec.SizeOfRawData, &ent);
            info.entropy = ent;
        }

        sections_.push_back(std::move(info));
    }

    return true;
}

std::vector<std::string> PEParser::GetImports()  const { return imports_;  }
std::vector<SectionInfo>  PEParser::GetSections() const { return sections_; }
bool     PEParser::Is64Bit()           const { return is64_;     }
bool     PEParser::HasDebugDirectory() const { return hasdebug_; }
bool     PEParser::IsDotNet()          const { return isdotnet_; }
uint64_t PEParser::GetTimestamp()      const { return timestamp_; }

} // namespace PhantomScope
