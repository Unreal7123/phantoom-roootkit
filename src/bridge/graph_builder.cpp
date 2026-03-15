// ============================================================================
// PhantomScope — graph_builder.cpp
// Graph Node & Edge Relationship Constructor
//
// Builds a directed graph from scan results for rendering in Cytoscape.js.
// Node types map directly to PhantomScope threat categories.
// Edge types represent relationships between processes, files, and services.
//
// Output: JSON string consumed by the Electron/React frontend via IPC.
// Format: { nodes: [...], edges: [...] } — Cytoscape.js elements format
// ============================================================================

#include "graph_builder.h"
#include "process_diff.h"
#include "file_scanner.h"
#include "vt_client.h"

#include <sstream>
#include <unordered_map>
#include <algorithm>
#include <cstdio>

namespace PhantomScope {

// ============================================================================
// Threat scoring logic
// ============================================================================
static uint32_t ComputeThreatScore(
    bool is_hidden, double entropy,
    int32_t vt_detections, bool is_signed,
    const std::string& path)
{
    uint32_t score = 0;

    // Hidden process: +60 points
    if (is_hidden) score += 60;

    // High entropy: +20 points
    if (entropy > 7.5) score += 30;
    else if (entropy > 6.5) score += 20;

    // VirusTotal detections: +40 points
    if (vt_detections > 0) score += 40;
    else if (vt_detections == 0) {}  // clean

    // Unsigned binary: +10 points
    if (!is_signed) score += 10;

    // Suspicious path: +15 points
    if (!path.empty()) {
        std::string lower_path = path;
        std::transform(lower_path.begin(), lower_path.end(),
                       lower_path.begin(), ::tolower);

        // User-writable temp directories are suspicious
        if (lower_path.find("\\temp\\") != std::string::npos ||
            lower_path.find("\\tmp\\") != std::string::npos ||
            lower_path.find("/tmp/") != std::string::npos ||
            lower_path.find("\\appdata\\roaming\\") != std::string::npos) {
            score += 15;
        }

        // Suspicious: executable in user profile, not in system dirs
        if (lower_path.find("\\users\\") != std::string::npos &&
            lower_path.find("\\windows\\") == std::string::npos) {
            score += 10;
        }
    }

    return std::min(score, 100u);
}

static ThreatLevel ScoreToThreatLevel(uint32_t score) {
    if (score >= 70) return ThreatLevel::Critical;
    if (score >= 40) return ThreatLevel::Suspicious;
    if (score >= 10) return ThreatLevel::Informational;
    return ThreatLevel::Clean;
}

static const char* ThreatLevelToString(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::Critical:      return "critical";
        case ThreatLevel::Suspicious:    return "suspicious";
        case ThreatLevel::Informational: return "informational";
        case ThreatLevel::Clean:         return "clean";
        default:                         return "unknown";
    }
}

static const char* ThreatLevelToColor(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::Critical:      return "#FF2D55";
        case ThreatLevel::Suspicious:    return "#FF9F0A";
        case ThreatLevel::Informational: return "#0A84FF";
        case ThreatLevel::Clean:         return "#30D158";
        default:                         return "#636366";
    }
}

// ============================================================================
// JSON escaping helper
// ============================================================================
static std::string JsonEscape(const std::string& s) {
    std::string result;
    result.reserve(s.size() * 2);
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n";  break;
            case '\r': result += "\\r";  break;
            case '\t': result += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x",
                             static_cast<unsigned>(c));
                    result += buf;
                } else {
                    result += c;
                }
        }
    }
    return result;
}

// ============================================================================
// GraphBuilder Implementation
// ============================================================================

GraphData GraphBuilder::Build(
    const ProcessDiffResult& proc_result,
    const FileScanResult& file_result,
    const std::vector<VTResult>& vt_results)
{
    GraphData graph;

    // Build VT lookup map keyed by MD5
    std::unordered_map<std::string, const VTResult*> vt_map;
    for (const auto& vt : vt_results) {
        vt_map[vt.md5] = &vt;
    }

    // Build file scan lookup map keyed by path
    std::unordered_map<std::string, const ScannedFile*> file_map;
    for (const auto& f : file_result.files) {
        file_map[f.path] = &f;
    }

    // Node ID generation
    uint64_t next_id = 1;
    std::unordered_map<std::string, std::string> node_id_map;  // path/pid → node_id

    auto MakeNodeId = [&](const std::string& key) -> std::string {
        auto it = node_id_map.find(key);
        if (it != node_id_map.end()) return it->second;
        std::string id = "n" + std::to_string(next_id++);
        node_id_map[key] = id;
        return id;
    };

    // ---- PROCESS NODES ----
    for (const auto& proc : proc_result.all_processes) {
        GraphNode node;
        node.id   = MakeNodeId("proc:" + std::to_string(proc.pid));
        node.type = proc.is_hidden ? NodeType::HiddenProcess : NodeType::Process;
        node.pid  = proc.pid;
        node.ppid = proc.ppid;
        node.name = proc.name;
        node.path = proc.path;

        // Get file scan info if available
        double entropy = 0.0;
        int32_t vt_det = -1;
        bool is_signed = true;

        auto file_it = file_map.find(proc.path);
        if (file_it != file_map.end()) {
            const auto* sf = file_it->second;
            entropy   = sf->entropy;
            is_signed = sf->is_signed;
            vt_det    = sf->vt_detections;

            if (!sf->md5.empty()) {
                auto vt_it = vt_map.find(sf->md5);
                if (vt_it != vt_map.end()) {
                    vt_det = vt_it->second->detections;
                    node.threat_name = vt_it->second->threat_name;
                }
            }
        }

        node.entropy       = entropy;
        node.vt_detections = vt_det;
        node.is_signed     = is_signed;
        node.is_hidden     = proc.is_hidden;
        node.score         = ComputeThreatScore(
            proc.is_hidden, entropy, vt_det, is_signed, proc.path);
        node.threat_level  = ScoreToThreatLevel(node.score);

        graph.nodes.push_back(std::move(node));

        // Edge: parent → child process
        if (proc.ppid > 0 && proc.ppid != proc.pid) {
            std::string parent_node_id = MakeNodeId(
                "proc:" + std::to_string(proc.ppid));

            GraphEdge edge;
            edge.id     = "e" + std::to_string(next_id++);
            edge.source = parent_node_id;
            edge.target = node_id_map["proc:" + std::to_string(proc.pid)];
            edge.type   = EdgeType::SpawnsProcess;
            edge.label  = "spawns";
            graph.edges.push_back(std::move(edge));
        }
    }

    // ---- FILE NODES ----
    for (const auto& f : file_result.files) {
        // Skip files already covered by process nodes
        bool covered = false;
        for (const auto& proc : proc_result.all_processes) {
            if (proc.path == f.path) { covered = true; break; }
        }

        GraphNode node;
        node.id   = MakeNodeId("file:" + f.path);
        node.type = NodeType::File;
        node.name = fs_basename(f.path);
        node.path = f.path;
        node.md5  = f.md5;
        node.entropy      = f.entropy;
        node.is_signed    = f.is_signed;
        node.is_hidden    = false;
        node.vt_detections = f.vt_detections;

        // VT lookup
        if (!f.md5.empty()) {
            auto vt_it = vt_map.find(f.md5);
            if (vt_it != vt_map.end()) {
                node.vt_detections = vt_it->second->detections;
                node.threat_name   = vt_it->second->threat_name;
            }
        }

        node.score        = ComputeThreatScore(
            false, f.entropy, node.vt_detections, f.is_signed, f.path);
        node.threat_level = ScoreToThreatLevel(node.score);

        graph.nodes.push_back(std::move(node));

        // Edges: file imports other DLLs
        for (const auto& dll : f.imported_dlls) {
            std::string dll_node_id = MakeNodeId("file:" + dll);

            // Create DLL node if not exists
            if (node_id_map.count("file:" + dll) == 0) {
                GraphNode dll_node;
                dll_node.id   = dll_node_id;
                dll_node.type = NodeType::File;
                dll_node.name = dll;
                dll_node.path = dll;
                dll_node.score = 0;
                dll_node.threat_level = ThreatLevel::Clean;
                graph.nodes.push_back(std::move(dll_node));
            }

            GraphEdge edge;
            edge.id     = "e" + std::to_string(next_id++);
            edge.source = node_id_map["file:" + f.path];
            edge.target = dll_node_id;
            edge.type   = EdgeType::ImportsModule;
            edge.label  = "imports";
            graph.edges.push_back(std::move(edge));
        }
    }

    // ---- GRAPH STATS ----
    graph.total_nodes = static_cast<uint32_t>(graph.nodes.size());
    graph.total_edges = static_cast<uint32_t>(graph.edges.size());
    graph.hidden_process_count = proc_result.hidden_count;

    for (const auto& n : graph.nodes) {
        if (n.threat_level == ThreatLevel::Critical)      ++graph.critical_count;
        else if (n.threat_level == ThreatLevel::Suspicious) ++graph.suspicious_count;
    }

    return graph;
}

// ============================================================================
// Serialize to Cytoscape.js JSON
// ============================================================================
std::string GraphBuilder::SerializeToJSON(const GraphData& graph) {
    std::ostringstream json;
    json << "{\n  \"nodes\": [\n";

    for (size_t i = 0; i < graph.nodes.size(); ++i) {
        const auto& n = graph.nodes[i];
        json << "    {\n";
        json << "      \"data\": {\n";
        json << "        \"id\": \"" << JsonEscape(n.id) << "\",\n";
        json << "        \"type\": \"" << NodeTypeToString(n.type) << "\",\n";
        json << "        \"name\": \"" << JsonEscape(n.name) << "\",\n";
        json << "        \"path\": \"" << JsonEscape(n.path) << "\",\n";
        json << "        \"md5\": \"" << JsonEscape(n.md5) << "\",\n";
        json << "        \"pid\": " << n.pid << ",\n";
        json << "        \"ppid\": " << n.ppid << ",\n";
        json << "        \"entropy\": " << n.entropy << ",\n";
        json << "        \"vtDetections\": " << n.vt_detections << ",\n";
        json << "        \"isSigned\": " << (n.is_signed ? "true" : "false") << ",\n";
        json << "        \"isHidden\": " << (n.is_hidden ? "true" : "false") << ",\n";
        json << "        \"score\": " << n.score << ",\n";
        json << "        \"threatLevel\": \"" << ThreatLevelToString(n.threat_level) << "\",\n";
        json << "        \"color\": \"" << ThreatLevelToColor(n.threat_level) << "\",\n";
        json << "        \"threatName\": \"" << JsonEscape(n.threat_name) << "\"\n";
        json << "      }\n";
        json << "    }";
        if (i < graph.nodes.size() - 1) json << ",";
        json << "\n";
    }

    json << "  ],\n  \"edges\": [\n";

    for (size_t i = 0; i < graph.edges.size(); ++i) {
        const auto& e = graph.edges[i];
        json << "    {\n";
        json << "      \"data\": {\n";
        json << "        \"id\": \"" << JsonEscape(e.id) << "\",\n";
        json << "        \"source\": \"" << JsonEscape(e.source) << "\",\n";
        json << "        \"target\": \"" << JsonEscape(e.target) << "\",\n";
        json << "        \"type\": \"" << EdgeTypeToString(e.type) << "\",\n";
        json << "        \"label\": \"" << JsonEscape(e.label) << "\"\n";
        json << "      }\n";
        json << "    }";
        if (i < graph.edges.size() - 1) json << ",";
        json << "\n";
    }

    json << "  ],\n";
    json << "  \"stats\": {\n";
    json << "    \"totalNodes\": " << graph.total_nodes << ",\n";
    json << "    \"totalEdges\": " << graph.total_edges << ",\n";
    json << "    \"hiddenProcesses\": " << graph.hidden_process_count << ",\n";
    json << "    \"criticalCount\": " << graph.critical_count << ",\n";
    json << "    \"suspiciousCount\": " << graph.suspicious_count << "\n";
    json << "  }\n";
    json << "}\n";

    return json.str();
}

std::string GraphBuilder::fs_basename(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

const char* GraphBuilder::NodeTypeToString(NodeType type) {
    switch (type) {
        case NodeType::Process:       return "PHProcess";
        case NodeType::HiddenProcess: return "PHHiddenProcess";
        case NodeType::File:          return "PHFile";
        case NodeType::Service:       return "PHService";
        case NodeType::Driver:        return "PHDriver";
        case NodeType::UnquotedSvc:   return "PHUnquotedSvc";
        default: return "PHUnknown";
    }
}

const char* GraphBuilder::EdgeTypeToString(EdgeType type) {
    switch (type) {
        case EdgeType::LoadsModule:   return "PHLoadsModule";
        case EdgeType::SpawnsProcess: return "PHSpawnsProcess";
        case EdgeType::HijackPath:    return "PHHijackPath";
        case EdgeType::RunsAs:        return "PHRunsAs";
        case EdgeType::ImportsModule: return "PHImports";
        case EdgeType::InjectsInto:   return "PHInjects";
        default: return "PHRelated";
    }
}

} // namespace PhantomScope
