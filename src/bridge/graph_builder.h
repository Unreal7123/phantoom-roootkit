#pragma once
#ifndef PHANTOMSCOPE_GRAPH_BUILDER_H
#define PHANTOMSCOPE_GRAPH_BUILDER_H

#include <string>
#include <vector>
#include <cstdint>
#include "process_diff.h"
#include "file_scanner.h"
#include "vt_client.h"

namespace PhantomScope {

enum class NodeType {
    Process, HiddenProcess, File, Service,
    Driver, UnquotedSvc, User
};

enum class EdgeType {
    LoadsModule, SpawnsProcess, HijackPath,
    RunsAs, ImportsModule, InjectsInto
};

enum class ThreatLevel {
    Clean, Informational, Suspicious, Critical
};

struct GraphNode {
    std::string id;
    NodeType    type;
    std::string name;
    std::string path;
    std::string md5;
    uint32_t    pid  = 0;
    uint32_t    ppid = 0;
    double      entropy = 0.0;
    int32_t     vt_detections = -1;
    bool        is_signed  = true;
    bool        is_hidden  = false;
    uint32_t    score      = 0;
    ThreatLevel threat_level = ThreatLevel::Clean;
    std::string threat_name;
};

struct GraphEdge {
    std::string id;
    std::string source;
    std::string target;
    EdgeType    type;
    std::string label;
};

struct GraphData {
    std::vector<GraphNode> nodes;
    std::vector<GraphEdge> edges;
    uint32_t total_nodes   = 0;
    uint32_t total_edges   = 0;
    uint32_t hidden_process_count = 0;
    uint32_t critical_count = 0;
    uint32_t suspicious_count = 0;
};

class GraphBuilder {
public:
    static GraphData Build(
        const ProcessDiffResult& proc_result,
        const FileScanResult& file_result,
        const std::vector<VTResult>& vt_results
    );

    static std::string SerializeToJSON(const GraphData& graph);

    static const char* NodeTypeToString(NodeType type);
    static const char* EdgeTypeToString(EdgeType type);

private:
    static std::string fs_basename(const std::string& path);
};

} // namespace PhantomScope

#endif
