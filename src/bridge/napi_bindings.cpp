// ============================================================================
// PhantomScope — napi_bindings.cpp
// Node.js N-API Native Addon Bindings
//
// Exposes the C++ bridge layer to the Electron main process via N-API.
// All heavy lifting is done in C++ (with ASM core) — this file is pure glue.
//
// Exported functions:
//   runProcessDiff()      → JS object with process/hidden arrays
//   scanPath(options)     → JS object with file scan results
//   scanSingleFile(path)  → JS object with single file data
//   vtLookup(md5, key)    → JS object with VT results
//   buildGraph(p, f, vt)  → JS object with graph JSON
//   getVersion()          → string "1.0.0"
// ============================================================================

#include <napi.h>
#include <string>
#include <vector>

#include "asm_bridge.h"
#include "process_diff.h"
#include "file_scanner.h"
#include "vt_client.h"
#include "graph_builder.h"

using namespace PhantomScope;

// ============================================================================
// Helpers: Convert C++ structs to N-API JS objects
// ============================================================================

static Napi::Object ProcessInfoToNapi(Napi::Env env, const ProcessInfo& p) {
    auto obj = Napi::Object::New(env);
    obj.Set("pid",          Napi::Number::New(env, p.pid));
    obj.Set("ppid",         Napi::Number::New(env, p.ppid));
    obj.Set("threadCount",  Napi::Number::New(env, p.thread_count));
    obj.Set("name",         Napi::String::New(env, p.name));
    obj.Set("path",         Napi::String::New(env, p.path));
    obj.Set("isHidden",     Napi::Boolean::New(env, p.is_hidden));
    obj.Set("fromKernel",   Napi::Boolean::New(env, p.from_kernel));
    obj.Set("fromUsermode", Napi::Boolean::New(env, p.from_usermode));
    obj.Set("score",        Napi::Number::New(env, p.threat_score));
    obj.Set("entropy",      Napi::Number::New(env, p.entropy));
    obj.Set("md5",          Napi::String::New(env, p.md5));
    obj.Set("vtDetections", Napi::Number::New(env, p.vt_detections));
    obj.Set("threatName",   Napi::String::New(env, p.threat_family));

    const char* level = p.threat_score >= 70 ? "critical" :
                        p.threat_score >= 40 ? "suspicious" :
                        p.threat_score >= 10 ? "informational" : "clean";
    obj.Set("threatLevel", Napi::String::New(env, level));

    return obj;
}

static Napi::Object ScannedFileToNapi(Napi::Env env, const ScannedFile& f) {
    auto obj = Napi::Object::New(env);
    obj.Set("path",          Napi::String::New(env, f.path));
    obj.Set("md5",           Napi::String::New(env, f.md5));
    obj.Set("entropy",       Napi::Number::New(env, f.entropy));
    obj.Set("entropyClass",  Napi::Number::New(env, f.entropy_class));
    obj.Set("fileSize",      Napi::Number::New(env, static_cast<double>(f.file_size)));
    obj.Set("isSigned",      Napi::Boolean::New(env, f.is_signed));
    obj.Set("vtDetections",  Napi::Number::New(env, f.vt_detections));
    obj.Set("threatName",    Napi::String::New(env, f.threat_name));
    obj.Set("score",         Napi::Number::New(env, f.threat_score));
    obj.Set("scanned",       Napi::Boolean::New(env, f.scanned));

    // Imported DLLs array
    auto dlls = Napi::Array::New(env, f.imported_dlls.size());
    for (size_t i = 0; i < f.imported_dlls.size(); ++i) {
        dlls.Set(i, Napi::String::New(env, f.imported_dlls[i]));
    }
    obj.Set("importedDlls", dlls);

    // Sections array
    auto sections = Napi::Array::New(env, f.sections.size());
    for (size_t i = 0; i < f.sections.size(); ++i) {
        const auto& s = f.sections[i];
        auto sec = Napi::Object::New(env);
        sec.Set("name",         Napi::String::New(env, s.name));
        sec.Set("virtualSize",  Napi::Number::New(env, s.virtual_size));
        sec.Set("rawSize",      Napi::Number::New(env, s.raw_size));
        sec.Set("entropy",      Napi::Number::New(env, s.entropy));
        sec.Set("isExecutable", Napi::Boolean::New(env, s.is_executable));
        sections.Set(i, sec);
    }
    obj.Set("sections", sections);

    const char* level = f.threat_score >= 70 ? "critical" :
                        f.threat_score >= 40 ? "suspicious" :
                        f.threat_score >= 10 ? "informational" : "clean";
    obj.Set("threatLevel", Napi::String::New(env, level));

    return obj;
}

// ============================================================================
// runProcessDiff()
// ============================================================================
static Napi::Value RunProcessDiff(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    try {
        ProcessDiffEngine engine;
        ProcessDiffResult result = engine.RunDiff();

        auto obj = Napi::Object::New(env);

        // All processes
        auto all_arr = Napi::Array::New(env, result.all_processes.size());
        for (size_t i = 0; i < result.all_processes.size(); ++i) {
            all_arr.Set(i, ProcessInfoToNapi(env, result.all_processes[i]));
        }
        obj.Set("allProcesses", all_arr);

        // Hidden processes
        auto hidden_arr = Napi::Array::New(env, result.hidden_processes.size());
        for (size_t i = 0; i < result.hidden_processes.size(); ++i) {
            hidden_arr.Set(i, ProcessInfoToNapi(env, result.hidden_processes[i]));
        }
        obj.Set("hiddenProcesses", hidden_arr);

        obj.Set("hiddenCount",   Napi::Number::New(env, result.hidden_count));
        obj.Set("kernelCount",   Napi::Number::New(env, result.kernel_count));
        obj.Set("usermodeCount", Napi::Number::New(env, result.usermode_count));

        return obj;

    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Undefined();
    }
}

// ============================================================================
// scanPath(options)
// ============================================================================
static Napi::Value ScanPath(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "Expected options object").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    auto opts_obj = info[0].As<Napi::Object>();

    ScanOptions opts;
    if (opts_obj.Has("rootPath")) {
        opts.root_path = opts_obj.Get("rootPath").As<Napi::String>().Utf8Value();
    }
    if (opts_obj.Has("maxFiles")) {
        opts.max_files = opts_obj.Get("maxFiles").As<Napi::Number>().Uint32Value();
    }
    opts.follow_symlinks = opts_obj.Has("followSymlinks")
        ? opts_obj.Get("followSymlinks").As<Napi::Boolean>().Value()
        : false;

    try {
        FileScanner scanner;
        FileScanResult result = scanner.ScanPath(opts);

        auto obj = Napi::Object::New(env);

        auto files_arr = Napi::Array::New(env, result.files.size());
        for (size_t i = 0; i < result.files.size(); ++i) {
            files_arr.Set(i, ScannedFileToNapi(env, result.files[i]));
        }
        obj.Set("files",            files_arr);
        obj.Set("highEntropyCount", Napi::Number::New(env, result.high_entropy_count));
        obj.Set("vtDetectedCount",  Napi::Number::New(env, result.vt_detected_count));
        obj.Set("unsignedCount",    Napi::Number::New(env, result.unsigned_count));
        obj.Set("success",          Napi::Boolean::New(env, result.success));

        if (!result.error_message.empty()) {
            obj.Set("error", Napi::String::New(env, result.error_message));
        }

        return obj;

    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Undefined();
    }
}

// ============================================================================
// scanSingleFile(filePath)
// ============================================================================
static Napi::Value ScanSingleFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected file path string").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::string path = info[0].As<Napi::String>().Utf8Value();

    try {
        FileScanner scanner;
        ScannedFile result = scanner.ScanSingleFile(path);
        return ScannedFileToNapi(env, result);
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Undefined();
    }
}

// ============================================================================
// vtLookup(md5, apiKey)
// ============================================================================
static Napi::Value VtLookup(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
        Napi::TypeError::New(env, "Expected (md5: string, apiKey: string)").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::string md5     = info[0].As<Napi::String>().Utf8Value();
    std::string api_key = info[1].As<Napi::String>().Utf8Value();

    try {
        VTClient client(api_key);
        VTResult result = client.LookupHash(md5);

        auto obj = Napi::Object::New(env);
        obj.Set("md5",           Napi::String::New(env, result.md5));
        obj.Set("sha256",        Napi::String::New(env, result.sha256));
        obj.Set("threatName",    Napi::String::New(env, result.threat_name));
        obj.Set("meaningfulName", Napi::String::New(env, result.meaningful_name));
        obj.Set("detections",    Napi::Number::New(env, result.detections));
        obj.Set("malicious",     Napi::Number::New(env, result.malicious));
        obj.Set("suspicious",    Napi::Number::New(env, result.suspicious));
        obj.Set("undetected",    Napi::Number::New(env, result.undetected));
        obj.Set("lookedUp",      Napi::Boolean::New(env, result.looked_up));
        obj.Set("foundInVT",     Napi::Boolean::New(env, result.found_in_vt));

        if (!result.error.empty()) {
            obj.Set("error", Napi::String::New(env, result.error));
        }

        return obj;

    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Undefined();
    }
}

// ============================================================================
// getVersion()
// ============================================================================
static Napi::Value GetVersion(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), "1.0.0");
}

// ============================================================================
// Module registration
// ============================================================================
static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Initialize ASM core (resolve SSNs, detect CPU features)
    AsmCore::Initialize();

    exports.Set("runProcessDiff",  Napi::Function::New(env, RunProcessDiff));
    exports.Set("scanPath",        Napi::Function::New(env, ScanPath));
    exports.Set("scanSingleFile",  Napi::Function::New(env, ScanSingleFile));
    exports.Set("vtLookup",        Napi::Function::New(env, VtLookup));
    exports.Set("getVersion",      Napi::Function::New(env, GetVersion));

    return exports;
}

NODE_API_MODULE(phantomscope, Init)
