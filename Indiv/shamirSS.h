#pragma once
#include <cstdint>
#include <vector>

struct Share {
    int64_t x;
    int64_t y;
};

// 2-of-N split
std::vector<Share> shamirSplit(
    int64_t secret,
    int N,
    int64_t prime);

// Reconstruct from any two shares
int64_t shamirReconstruct(
    const Share& s1,
    const Share& s2,
    int64_t prime);