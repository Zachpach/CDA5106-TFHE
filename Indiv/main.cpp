/*
    Final Project - CDA5106 Spring 2026
    TFHE (Torus Fully Homomorphic Encryption) Simulator
*/

#include <iostream>
#include <vector>
#include <cstdint>
#include <cmath>
#include <random>
#include <iomanip>
#include <string>
#include <sstream>

#include "shamirSS.h"

using Torus = int32_t;

// Fixed RNG seed for reproducibility
std::mt19937 rng(10);

// Ciphertext structure
struct Ciphertext 
{
    std::vector<Torus> randomMask;
    Torus hiddenValue;
};

// Torus helpers
Torus toTorus(double value) 
{
    return (Torus)(std::fmod(value, 1.0) * (1LL << 32));
}

std::string tstr(Torus t) 
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(5)
        << (double)t / (1LL << 32);

    return oss.str();
}

Torus smallNoise(double stddev) 
{
    double sample =
        std::normal_distribution<double>(0, stddev)(rng);

    return toTorus(sample);
}

// TFHE key operations
Torus dotProduct(const std::vector<Torus>& mask, const std::vector<int32_t>& keyBits) 
{
    Torus sum = 0;
    for (int i = 0; i < (int)mask.size(); i++)
        sum += mask[i] * keyBits[i];

    return sum;
}

Torus encodeBit(int bit) 
{
    return bit ? (1 << 30) : 0;
}

int decodeBit(Torus value) 
{
    Torus d0 = std::abs(value);
    Torus d1 = std::abs(value - (1 << 30));

    return d1 < d0 ? 1 : 0;
}

// Encrypt / Decrypt
Ciphertext encrypt(int bit, const std::vector<int32_t>& key, double noiseLevel) 
{
    Ciphertext ct;
    ct.randomMask.resize(key.size());

    for (auto& v : ct.randomMask)
        v = std::uniform_int_distribution<int32_t>(
                INT32_MIN, INT32_MAX)(rng);

    Torus binding = dotProduct(ct.randomMask, key);
    Torus encoded = encodeBit(bit);
    Torus noise = smallNoise(noiseLevel);

    ct.hiddenValue = binding + encoded + noise;

    return ct;
}

int decrypt(const Ciphertext& ct, const std::vector<int32_t>& key) 
{
    Torus binding = dotProduct(ct.randomMask, key);
    Torus recovered = ct.hiddenValue - binding;

    return decodeBit(recovered);
}

// Homomorphic NAND
Ciphertext homNAND(const Ciphertext& a, const Ciphertext& b) 
{
    Ciphertext out;
    out.randomMask.resize(a.randomMask.size());

    for (int i = 0; i < (int)a.randomMask.size(); i++)
        out.randomMask[i] = -a.randomMask[i] - b.randomMask[i];

    out.hiddenValue = toTorus(5.0 / 8.0) - a.hiddenValue - b.hiddenValue;

    return out;
}

// MAIN
int main() 
{

    const int KEY_DIMENSION = 16;
    const double NOISE_STDDEV = 1.0 / (1 << 10);
    const int INPUT[4] = {0, 1, 0, 0};

    std::cout << "PROGRAM STARTED\n";

    // SHAMIR SECRET SHARING (2-of-3)
    const int64_t PRIME = 65537;

    int64_t masterSecret = 12345;

    // Split master key into N shares
    auto shares = shamirSplit(masterSecret, 3, PRIME);

    // Reconstruct key using any 2 shares
    int64_t recoveredSecret =
        shamirReconstruct(shares[0], shares[2], PRIME);

    // Convert recovered secret -> TFHE key bits
    std::vector<int32_t> key(KEY_DIMENSION);
    for (int i = 0; i < KEY_DIMENSION; i++) 
    {
        key[i] = (recoveredSecret >> (i % 31)) & 1;
    }

    // ENCRYPT -> DECRYPT TEST
    std::cout << "\nENCRYPT -> DECRYPT\n";
    for (int bit : INPUT) 
    {
        Ciphertext ct = encrypt(bit, key, NOISE_STDDEV);
        int out = decrypt(ct, key);
        std::cout << "  "
                  << bit << " -> " << out
                  << (bit == out ? " PASS\n" : " FAIL\n");
    }

    // HOMOMORPHIC NAND TEST
    std::cout << "\nHOMOMORPHIC NAND\n";
    for (int x : {0, 1}) 
    {
        for (int y : {0, 1}) 
        {
            int expected = !(x & y);
            Ciphertext ex = encrypt(x, key, NOISE_STDDEV);
            Ciphertext ey = encrypt(y, key, NOISE_STDDEV);
            Ciphertext r = homNAND(ex, ey);
            int got = decrypt(r, key);

            std::cout << "  NAND(" << x << ","
                      << y << ") -> "
                      << got
                      << (got == expected ? " PASS\n"
                                          : " FAIL\n");
        }
    }

    std::cout << "\nPROGRAM FINISHED\n";
    std::cin.get(); 
    return 0;
}
