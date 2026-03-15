{
  "targets": [
    {
      "target_name": "phantomscope",
      "sources": [
        "src/bridge/asm_bridge.cpp",
        "src/bridge/process_diff.cpp",
        "src/bridge/vt_client.cpp",
        "src/bridge/file_scanner.cpp",
        "src/bridge/graph_builder.cpp",
        "src/bridge/napi_bindings.cpp"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "src/bridge"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS",
        "NAPI_VERSION=8"
      ],
      "conditions": [
        [
          "OS=='win'",
          {
            "sources": [
              "src/bridge/pe_parser.cpp"
            ],
            "libraries": [
              "-lntdll",
              "-lkernel32",
              "-ladvapi32",
              "-lwintrust",
              "-lcrypt32"
            ],
            "defines": ["PHANTOMSCOPE_WINDOWS=1", "_WIN32_WINNT=0x0A00"],
            "msvs_settings": {
              "VCCLCompilerTool": {
                "ExceptionHandling": 1,
                "Optimization": 2,
                "AdditionalOptions": ["/std:c++17"]
              }
            }
          }
        ],
        [
          "OS=='linux'",
          {
            "sources": [
              "src/bridge/elf_parser.cpp"
            ],
            "libraries": [
              "-ldl",
              "-lpthread",
              "-lcurl"
            ],
            "defines": ["PHANTOMSCOPE_LINUX=1"],
            "cflags_cc": [
              "-std=c++17",
              "-O2",
              "-Wall",
              "-Wextra"
            ]
          }
        ]
      ]
    }
  ]
}
