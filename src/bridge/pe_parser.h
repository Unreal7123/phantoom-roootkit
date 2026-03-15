// pe_parser.h
#pragma once
#include <string>
#include <vector>
#include "file_scanner.h"

namespace PhantomScope {
class PEParser {
public:
    explicit PEParser(const std::string& path);
    bool Parse();
    std::vector<std::string> GetImports() const;
    std::vector<SectionInfo>  GetSections() const;
    bool Is64Bit() const;
    bool HasDebugDirectory() const;
    bool IsDotNet() const;
    uint64_t GetTimestamp() const;
private:
    std::string path_;
    bool parsed_ = false;
    bool is64_ = false;
    bool hasdebug_ = false;
    bool isdotnet_ = false;
    uint64_t timestamp_ = 0;
    std::vector<std::string> imports_;
    std::vector<SectionInfo> sections_;
};
}
