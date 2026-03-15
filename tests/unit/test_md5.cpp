// ============================================================================
// PhantomScope — tests/unit/test_md5.cpp
// MD5 Validation Test Suite
// ============================================================================

#include <cstdio>
#include <cstring>
#include <cassert>
#include <string>

extern "C" {
    int AsmMD5Compute(const unsigned char* data, unsigned long long length, unsigned char* output);
}

static void FormatHex(const unsigned char* digest, char* hex) {
    static const char hexchars[] = "0123456789abcdef";
    for (int i = 0; i < 16; ++i) {
        hex[i*2]   = hexchars[(digest[i] >> 4) & 0x0F];
        hex[i*2+1] = hexchars[digest[i] & 0x0F];
    }
    hex[32] = 0;
}

struct MD5TestVector {
    const char* input;
    const char* expected;
};

// RFC 1321 test vectors
static MD5TestVector test_vectors[] = {
    { "",                               "d41d8cd98f00b204e9800998ecf8427e" },
    { "a",                              "0cc175b9c0f1b6a831c399e269772661" },
    { "abc",                            "900150983cd24fb0d6963f7d28e17f72" },
    { "message digest",                 "f96b697d7cb7938d525a2f31aaf161d0" },
    { "abcdefghijklmnopqrstuvwxyz",     "c3fcd3d76192e4007dfb496cca67e13b" },
    { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                                        "d174ab98d277d9f5a5611c2c9f419d9f" },
    { "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                                        "57edf4a22be3c955ac49da2e2107b67a" },
};

int main() {
    int passed = 0;
    int failed = 0;

    printf("PhantomScope MD5 Engine — RFC 1321 Test Vectors\n");
    printf("================================================\n\n");

    for (const auto& tv : test_vectors) {
        unsigned char digest[16];
        char hex[33];

        int ret = AsmMD5Compute(
            reinterpret_cast<const unsigned char*>(tv.input),
            strlen(tv.input),
            digest
        );

        FormatHex(digest, hex);

        bool ok = (ret == 0) && (strcmp(hex, tv.expected) == 0);

        if (ok) {
            printf("[PASS] MD5(\"%s\") = %s\n", tv.input, hex);
            ++passed;
        } else {
            printf("[FAIL] MD5(\"%s\")\n", tv.input);
            printf("       Expected: %s\n", tv.expected);
            printf("       Got:      %s\n", hex);
            ++failed;
        }
    }

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
