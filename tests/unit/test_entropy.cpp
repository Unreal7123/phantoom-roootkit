// ============================================================================
// PhantomScope — tests/unit/test_entropy.cpp
// Entropy Calculation Validation Suite
// ============================================================================

#include <cstdio>
#include <cstring>
#include <cassert>
#include <cmath>
#include <vector>
#include <cstdint>
#include <random>

extern "C" {
    int AsmEntropyCalc(const unsigned char* data, unsigned long long length, double* out);
}

struct EntropyTestCase {
    const char* name;
    double      expected_min;
    double      expected_max;
    int         expected_class;  // 0=clean, 1=suspicious, 2=encrypted
    std::vector<uint8_t> data;
};

// Build test data vectors
static std::vector<uint8_t> make_zeros(size_t n) {
    return std::vector<uint8_t>(n, 0x00);
}

static std::vector<uint8_t> make_uniform(size_t n) {
    std::vector<uint8_t> v(256);
    // Perfect uniform distribution: exactly 1 of each byte, repeated
    for (size_t i = 0; i < n; ++i) v.push_back(static_cast<uint8_t>(i % 256));
    return v;
}

static std::vector<uint8_t> make_pseudo_random(size_t n) {
    std::vector<uint8_t> v(n);
    std::mt19937 rng(0xDEADBEEF);
    for (auto& b : v) b = static_cast<uint8_t>(rng() & 0xFF);
    return v;
}

static std::vector<uint8_t> make_text_like(size_t n) {
    // ASCII printable characters — lower entropy
    const char* alphabet = "abcdefghijklmnopqrstuvwxyz ABCDEF0123456789.,\n";
    size_t len = strlen(alphabet);
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(alphabet[i % len]);
    return v;
}

int main() {
    printf("PhantomScope Entropy Engine — Validation Suite\n");
    printf("===============================================\n\n");

    int passed = 0, failed = 0;

    auto test = [&](const char* name, const std::vector<uint8_t>& data,
                    double exp_min, double exp_max, int exp_class)
    {
        double entropy = 0.0;
        int cls = AsmEntropyCalc(data.data(), data.size(), &entropy);

        bool ok = (entropy >= exp_min) && (entropy <= exp_max) && (cls == exp_class);

        printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
        printf("     H = %.6f  class = %d  (expected [%.2f,%.2f] class=%d)\n",
               entropy, cls, exp_min, exp_max, exp_class);

        if (ok) ++passed; else ++failed;
    };

    // All zeros — minimum entropy (H = 0)
    test("All zeros (4096 bytes)",
         make_zeros(4096),
         0.0, 0.01,
         0 /* clean */);

    // Text-like — low entropy
    test("ASCII text-like (4096 bytes)",
         make_text_like(4096),
         3.5, 5.5,
         0 /* clean */);

    // Pseudo-random — near maximum entropy (~8.0)
    test("Pseudo-random bytes (65536 bytes)",
         make_pseudo_random(65536),
         7.5, 8.0,
         2 /* encrypted */);

    // 256-byte uniform — perfect entropy = 8.0
    {
        std::vector<uint8_t> perfect(256);
        for (int i = 0; i < 256; ++i) perfect[i] = static_cast<uint8_t>(i);
        test("Perfect uniform distribution (256 bytes)",
             perfect,
             7.9, 8.0,
             2 /* encrypted */);
    }

    // Threshold boundary: entropy just above 6.5 = suspicious
    {
        // Construct a distribution with entropy ≈ 6.7
        // Use ~90 distinct byte values with near-uniform distribution
        std::vector<uint8_t> boundary;
        for (int rep = 0; rep < 256; ++rep)
            for (int b = 0; b < 90; ++b)
                boundary.push_back(static_cast<uint8_t>(b));
        test("Above 6.5 threshold (suspicious)",
             boundary,
             6.4, 6.8,
             1 /* suspicious */);
    }

    // Small file (< 64 bytes — below SIMD chunk size)
    {
        std::vector<uint8_t> small = { 'H','e','l','l','o',' ','W','o','r','l','d' };
        test("Small file (11 bytes, text)",
             small,
             2.0, 4.0,
             0 /* clean */);
    }

    // Exactly 64 bytes — one SIMD chunk
    test("Exactly 64 bytes (random)",
         make_pseudo_random(64),
         5.0, 8.0,
         1 /* at least suspicious */);

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
