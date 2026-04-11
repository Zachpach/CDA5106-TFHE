#include "shamirSS.h"
#include <random>
#include <stdexcept>

// Modular inverse using extended Euclid 64
static int64_t modInverse(int64_t a, int64_t p) 
{
    int64_t t = 0, newT = 1;
    int64_t r = p, newR = a;

    while (newR != 0) 
    {
        int64_t q = r / newR;
        int64_t tempT = t - q * newT;
        t = newT;
        newT = tempT;

        int64_t tempR = r - q * newR;
        r = newR;
        newR = tempR;
    }

    if (r != 1)
        throw std::runtime_error("No inverse");

    if (t < 0) 
        t += p;
        
    return t;
}

std::vector<Share> shamirSplit(int64_t secret, int N, int64_t prime)
{
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<int64_t> dist(1, prime - 1);

    int64_t a = dist(rng); // slope
    std::vector<Share> shares;

    for (int i = 1; i <= N; i++) 
    {
        int64_t x = i;
        int64_t y = (secret + a * x) % prime;
        shares.push_back({x, y});
    }
    return shares;
}

int64_t shamirReconstruct(const Share& s1, const Share& s2, int64_t prime)
{
    int64_t x1 = s1.x, y1 = s1.y;
    int64_t x2 = s2.x, y2 = s2.y;

    int64_t denom1 = (x1 - x2 + prime) % prime;
    int64_t denom2 = (x2 - x1 + prime) % prime;

    int64_t inv1 = modInverse(denom1, prime);
    int64_t inv2 = modInverse(denom2, prime);

    int64_t term1 = (y1 * x2 % prime) * inv1 % prime;
    int64_t term2 = (y2 * x1 % prime) * inv2 % prime;

    int64_t secret = (term1 + term2) % prime;

    if (secret < 0) 
        secret += prime;

    return secret;
}
