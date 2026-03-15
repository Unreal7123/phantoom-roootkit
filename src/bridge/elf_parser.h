// elf_parser.h
#pragma once
#include <string>
#include <vector>
#include "file_scanner.h"

namespace PhantomScope {
class ELFParser {
public:
    explicit ELFParser(const std::string& path);
    bool Parse();
    std::vector<std::string> GetDependencies() const;
    std::vector<SectionInfo>  GetSections() const;
    bool Is64Bit() const;
private:
    std::string path_;
    bool parsed_ = false;
    bool is64_ = false;
    std::vector<std::string> deps_;
    std::vector<SectionInfo> sections_;
};
}
