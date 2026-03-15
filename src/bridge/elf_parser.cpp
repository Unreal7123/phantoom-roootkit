// ============================================================================
// PhantomScope — elf_parser.cpp
// ELF (Executable and Linkable Format) Binary Parser — Linux
//
// Manually parses ELF headers to extract:
//   - PT_DYNAMIC segment → DT_NEEDED entries (shared library dependencies)
//   - Section headers → entropy per section
//   - ELF class (32/64-bit), architecture
//   - Stripped binary detection
//
// Supports ELF32 and ELF64 (x86-64 primary target).
// Memory-mapped for zero-copy parsing.
// ============================================================================

#include "elf_parser.h"
#include "asm_bridge.h"

#include <cstring>
#include <algorithm>
#include <stdexcept>

#ifndef _WIN32
  #include <sys/mman.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <unistd.h>
  #include <elf.h>
#else
  // Windows stub definitions for cross-compilation
  #define ELFMAG      "\177ELF"
  #define SELFMAG     4
  #define ELFCLASS64  2
  #define ELFCLASS32  1
  #define PT_DYNAMIC  2
  #define PT_LOAD     1
  #define DT_NEEDED   1
  #define DT_NULL     0
  #define DT_STRTAB   5
  #define DT_STRSZ    10
  #define SHF_EXECINSTR 0x4
  #define SHF_WRITE     0x1
  #define SHT_NULL    0
  #define SHT_STRTAB  3
  #pragma pack(push,1)
  typedef uint64_t Elf64_Addr, Elf64_Off, Elf64_Xword;
  typedef uint32_t Elf64_Word;
  typedef int64_t  Elf64_Sxword;
  typedef uint16_t Elf64_Half;
  struct Elf64_Ehdr { unsigned char e_ident[16]; Elf64_Half e_type,e_machine; Elf64_Word e_version; Elf64_Addr e_entry; Elf64_Off e_phoff,e_shoff; Elf64_Word e_flags; Elf64_Half e_ehsize,e_phentsize,e_phnum,e_shentsize,e_shnum,e_shstrndx; };
  struct Elf64_Phdr { Elf64_Word p_type,p_flags; Elf64_Off p_offset; Elf64_Addr p_vaddr,p_paddr; Elf64_Xword p_filesz,p_memsz,p_align; };
  struct Elf64_Shdr { Elf64_Word sh_name,sh_type; Elf64_Xword sh_flags; Elf64_Addr sh_addr; Elf64_Off sh_offset; Elf64_Xword sh_size; Elf64_Word sh_link,sh_info; Elf64_Xword sh_addralign,sh_entsize; };
  struct Elf64_Dyn  { Elf64_Sxword d_tag; union { Elf64_Xword d_val; Elf64_Addr d_ptr; } d_un; };
  typedef uint32_t Elf32_Addr, Elf32_Off, Elf32_Word;
  typedef int32_t  Elf32_Sword;
  typedef uint16_t Elf32_Half;
  struct Elf32_Ehdr { unsigned char e_ident[16]; Elf32_Half e_type,e_machine; Elf32_Word e_version; Elf32_Addr e_entry; Elf32_Off e_phoff,e_shoff; Elf32_Word e_flags; Elf32_Half e_ehsize,e_phentsize,e_phnum,e_shentsize,e_shnum,e_shstrndx; };
  struct Elf32_Phdr { Elf32_Word p_type; Elf32_Off p_offset; Elf32_Addr p_vaddr,p_paddr; Elf32_Word p_filesz,p_memsz,p_flags,p_align; };
  struct Elf32_Dyn  { Elf32_Sword d_tag; union { Elf32_Word d_val; Elf32_Addr d_ptr; } d_un; };
  struct Elf32_Shdr { Elf32_Word sh_name,sh_type,sh_flags; Elf32_Addr sh_addr; Elf32_Off sh_offset; Elf32_Word sh_size,sh_link,sh_info,sh_addralign,sh_entsize; };
  #pragma pack(pop)
#endif

namespace PhantomScope {

ELFParser::ELFParser(const std::string& path)
    : path_(path) {}

bool ELFParser::Parse() {
    if (parsed_) return true;

    const uint8_t* base  = nullptr;
    uint64_t       fsize = 0;

#ifndef _WIN32
    int fd = open(path_.c_str(), O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return false; }
    fsize = static_cast<uint64_t>(st.st_size);

    if (fsize < sizeof(Elf64_Ehdr)) { close(fd); return false; }

    void* mptr = mmap(nullptr, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mptr == MAP_FAILED) return false;

    madvise(mptr, fsize, MADV_SEQUENTIAL);
    base = static_cast<const uint8_t*>(mptr);
#else
    return false;  // ELF parsing not applicable on Windows builds
#endif

    bool result = ParseFromMemory(base, fsize);

#ifndef _WIN32
    munmap(const_cast<uint8_t*>(base), fsize);
#endif

    parsed_ = result;
    return result;
}

bool ELFParser::ParseFromMemory(const uint8_t* base, uint64_t size) {
    // Validate ELF magic
    if (size < SELFMAG || memcmp(base, ELFMAG, SELFMAG) != 0) return false;

    uint8_t elf_class = base[4];  // EI_CLASS

    if (elf_class == ELFCLASS64) {
        return ParseELF64(base, size);
    } else if (elf_class == ELFCLASS32) {
        return ParseELF32(base, size);
    }
    return false;
}

bool ELFParser::ParseELF64(const uint8_t* base, uint64_t size) {
    is64_ = true;
    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(base);

    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) return true;  // No program headers
    if (ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf64_Phdr) > size) return false;

    const auto* phdrs = reinterpret_cast<const Elf64_Phdr*>(base + ehdr->e_phoff);

    // Walk program headers looking for PT_DYNAMIC
    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        if (phdrs[i].p_type != PT_DYNAMIC) continue;

        uint64_t dyn_off  = phdrs[i].p_offset;
        uint64_t dyn_size = phdrs[i].p_filesz;

        if (dyn_off + dyn_size > size) break;

        // PT_DYNAMIC contains an array of Elf64_Dyn entries
        // We need DT_STRTAB and DT_STRSZ to resolve DT_NEEDED strings

        const auto* dyn = reinterpret_cast<const Elf64_Dyn*>(base + dyn_off);
        uint64_t    num_dyn = dyn_size / sizeof(Elf64_Dyn);

        uint64_t strtab_vaddr = 0;
        uint64_t strtab_size  = 0;

        // First pass: find string table
        for (uint64_t j = 0; j < num_dyn; ++j) {
            if (dyn[j].d_tag == DT_STRTAB) strtab_vaddr = dyn[j].d_un.d_val;
            if (dyn[j].d_tag == DT_STRSZ)  strtab_size  = dyn[j].d_un.d_val;
            if (dyn[j].d_tag == DT_NULL)    break;
        }

        // Convert strtab virtual address to file offset via PT_LOAD segments
        uint64_t strtab_off = VaddrToOffset64(strtab_vaddr, phdrs, ehdr->e_phnum, size);
        if (strtab_off == 0 || strtab_off + strtab_size > size) break;

        // Second pass: collect DT_NEEDED entries
        for (uint64_t j = 0; j < num_dyn; ++j) {
            if (dyn[j].d_tag == DT_NULL) break;

            if (dyn[j].d_tag == DT_NEEDED) {
                uint64_t name_off = strtab_off + dyn[j].d_un.d_val;
                if (name_off < size) {
                    std::string lib(reinterpret_cast<const char*>(base + name_off));
                    if (!lib.empty()) deps_.push_back(lib);
                }
            }
        }
        break;  // Only one PT_DYNAMIC segment
    }

    // Section headers for entropy analysis
    if (ehdr->e_shoff && ehdr->e_shnum &&
        ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr) <= size)
    {
        const auto* shdrs = reinterpret_cast<const Elf64_Shdr*>(base + ehdr->e_shoff);

        // Section name string table
        const char* shstrtab = nullptr;
        if (ehdr->e_shstrndx < ehdr->e_shnum) {
            uint64_t shstr_off = shdrs[ehdr->e_shstrndx].sh_offset;
            if (shstr_off < size) {
                shstrtab = reinterpret_cast<const char*>(base + shstr_off);
            }
        }

        for (uint16_t i = 0; i < ehdr->e_shnum; ++i) {
            const auto& shdr = shdrs[i];
            if (shdr.sh_type == SHT_NULL || shdr.sh_size == 0) continue;
            if (shdr.sh_offset + shdr.sh_size > size) continue;

            SectionInfo info;
            info.virtual_size   = static_cast<uint32_t>(shdr.sh_size);
            info.raw_size       = static_cast<uint32_t>(shdr.sh_size);
            info.is_executable  = (shdr.sh_flags & SHF_EXECINSTR) != 0;
            info.is_writable    = (shdr.sh_flags & SHF_WRITE)     != 0;

            // Get section name
            if (shstrtab && shdr.sh_name) {
                info.name = std::string(shstrtab + shdr.sh_name);
            } else {
                info.name = "[section_" + std::to_string(i) + "]";
            }

            // Compute entropy
            double ent = 0.0;
            AsmEntropyCalc(base + shdr.sh_offset, shdr.sh_size, &ent);
            info.entropy = ent;

            sections_.push_back(std::move(info));
        }
    }

    return true;
}

bool ELFParser::ParseELF32(const uint8_t* base, uint64_t size) {
    is64_ = false;
    const auto* ehdr = reinterpret_cast<const Elf32_Ehdr*>(base);

    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) return true;
    if (ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf32_Phdr) > size) return false;

    const auto* phdrs = reinterpret_cast<const Elf32_Phdr*>(base + ehdr->e_phoff);

    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        if (phdrs[i].p_type != PT_DYNAMIC) continue;

        uint32_t dyn_off  = phdrs[i].p_offset;
        uint32_t dyn_size = phdrs[i].p_filesz;
        if (dyn_off + dyn_size > size) break;

        const auto* dyn     = reinterpret_cast<const Elf32_Dyn*>(base + dyn_off);
        uint32_t    num_dyn = dyn_size / sizeof(Elf32_Dyn);

        uint32_t strtab_vaddr = 0, strtab_size = 0;
        for (uint32_t j = 0; j < num_dyn; ++j) {
            if (dyn[j].d_tag == DT_STRTAB) strtab_vaddr = dyn[j].d_un.d_val;
            if (dyn[j].d_tag == DT_STRSZ)  strtab_size  = dyn[j].d_un.d_val;
            if (dyn[j].d_tag == DT_NULL)    break;
        }

        uint32_t strtab_off = VaddrToOffset32(strtab_vaddr, phdrs, ehdr->e_phnum);
        if (!strtab_off || strtab_off + strtab_size > size) break;

        for (uint32_t j = 0; j < num_dyn; ++j) {
            if (dyn[j].d_tag == DT_NULL) break;
            if (dyn[j].d_tag == DT_NEEDED) {
                uint32_t name_off = strtab_off + dyn[j].d_un.d_val;
                if (name_off < size) {
                    std::string lib(reinterpret_cast<const char*>(base + name_off));
                    if (!lib.empty()) deps_.push_back(lib);
                }
            }
        }
        break;
    }

    return true;
}

uint64_t ELFParser::VaddrToOffset64(
    uint64_t vaddr,
    const Elf64_Phdr* phdrs,
    uint16_t num_phdrs,
    uint64_t file_size) const
{
    for (uint16_t i = 0; i < num_phdrs; ++i) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        uint64_t seg_start = phdrs[i].p_vaddr;
        uint64_t seg_end   = seg_start + phdrs[i].p_filesz;
        if (vaddr >= seg_start && vaddr < seg_end) {
            uint64_t off = phdrs[i].p_offset + (vaddr - seg_start);
            if (off < file_size) return off;
        }
    }
    return 0;
}

uint32_t ELFParser::VaddrToOffset32(
    uint32_t vaddr,
    const Elf32_Phdr* phdrs,
    uint16_t num_phdrs) const
{
    for (uint16_t i = 0; i < num_phdrs; ++i) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        uint32_t seg_start = phdrs[i].p_vaddr;
        uint32_t seg_end   = seg_start + phdrs[i].p_filesz;
        if (vaddr >= seg_start && vaddr < seg_end) {
            return phdrs[i].p_offset + (vaddr - seg_start);
        }
    }
    return 0;
}

std::vector<std::string> ELFParser::GetDependencies() const { return deps_;     }
std::vector<SectionInfo>  ELFParser::GetSections()     const { return sections_; }
bool                      ELFParser::Is64Bit()          const { return is64_;     }

} // namespace PhantomScope
