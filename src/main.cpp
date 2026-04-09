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
 
using Torus = int32_t;
// Fixed seed for reproducible runs
std::mt19937 rng(10);

// RandomMask - public random vector, one Torus value per key bit
// HiddenValue - the message locked behind the key: <mask,key> + msg + noise
struct Ciphertext {
    std::vector<Torus> randomMask;
    Torus hiddenValue;
};

// Takes in a decimal value in [0, 1) and returns the equivalent Torus integer, e.g. 2^30 (= 1073741824)
Torus toTorus(double value) {
    return (Torus)(std::fmod(value, 1.0) * (1LL << 32));
}
 
// Display a torus value as a short decimal fraction
std::string tstr(Torus t) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(5) << (double)t / (1LL << 32);
    return oss.str();
}
  
// Takes an input that controls the maximum size of the noise and returns 
// a tiny random Torus integer from a Gaussian distribution
Torus smallNoise(double stddev) {
    double sample = std::normal_distribution<double>(0, stddev)(rng);
    return toTorus(sample);
}
 
// Returns a key with 'dimension' random bits
std::vector<int32_t> generateKey(int dimension) {
    std::vector<int32_t> key(dimension);
    for (auto& bit : key)
        bit = std::uniform_int_distribution<int32_t>(0, 1)(rng);
    return key;
}
 
// Takes the mask and secret key as inputs and returns the dot product of the two.
Torus dotProduct(const std::vector<Torus>& mask, const std::vector<int32_t>& keyBits) {
    Torus sum = 0;
    for (int i = 0; i < (int)mask.size(); i++)
        sum += mask[i] * keyBits[i];
    return sum;
}
 
// Encodes bits as 0 -> 0.0, 1 -> 0.25. (Torus Logic)
Torus encodeBit(int bit) { return bit ? (1 << 30) : 0; }
 
// Takes the input value - recovered torus value (message + residual noise)
// Returns 0 if closer to 0.0,  1 if closer to 0.25
int decodeBit(Torus value) {
    Torus distanceToZero = std::abs(value);
    Torus distanceToQuarter = std::abs(value - (1 << 30));
    return distanceToQuarter < distanceToZero ? 1 : 0;
}
 
//   Input:  bit - plaintext bit to hide (0 or 1)
//           key - secret key used to lock the message
//           noiseLevel - Gaussian noise std-dev
//   Output: Ciphertext (randomMask[], hiddenValue)
Ciphertext encrypt(int bit, const std::vector<int32_t>& key, double noiseLevel) {
    Ciphertext ct;
    ct.randomMask.resize(key.size());
    for (auto& v : ct.randomMask) v = std::uniform_int_distribution<int32_t>(INT32_MIN, INT32_MAX)(rng);

    Torus keyBinding = dotProduct(ct.randomMask, key);
    Torus encodedBit = encodeBit(bit);
    Torus securityNoise = smallNoise(noiseLevel);

    //   Formula: hiddenValue = <randomMask, key> + encodeBit(bit) + noise
    ct.hiddenValue = keyBinding + encodedBit + securityNoise;
 
    std::cout << "         bit " << bit << " -> [torus] " << tstr(encodedBit)
              << "  +  [binding] " << tstr(keyBinding)
              << "  +  [noise] " << tstr(securityNoise)
              << "  =  [hidden] " << tstr(ct.hiddenValue) << "\n";
 
    return ct;
}
 
//   Input:  ct - Ciphertext from encrypt()
//           key - the same secret key used during encryption
//   Output: the original plaintext bit (0 or 1)
int decrypt(const Ciphertext& ct, const std::vector<int32_t>& key) {
    ///  Formula: strip binding -> encodedBit + noise -> round to nearest
    Torus keyBinding = dotProduct(ct.randomMask, key);
    Torus encodedPlusNoise = ct.hiddenValue - keyBinding;
    int result = decodeBit(encodedPlusNoise);
 
    std::cout << "         [hidden] " << tstr(ct.hiddenValue)
              << "  -  [binding] " << tstr(keyBinding)
              << "  =  " << tstr(encodedPlusNoise)
              << "  ->  bit = " << result << "\n";
 
    return result;
}
 
//   Input:  ct1 - Ciphertext encrypting bit x
//           ct2 - Ciphertext encrypting bit y
//   Output: Ciphertext encrypting NAND(x, y)  - no key used
Ciphertext homNAND(const Ciphertext& ct1, const Ciphertext& ct2) {
    Ciphertext output;
    output.randomMask.resize(ct1.randomMask.size());
    for (int i = 0; i < (int)ct1.randomMask.size(); i++)
        output.randomMask[i] = -ct1.randomMask[i] - ct2.randomMask[i];

    //   Formula: output = (5/8) - ct1 - ct2
    output.hiddenValue = toTorus(5.0 / 8.0) - ct1.hiddenValue - ct2.hiddenValue;
 
    return output;
}
 
// MULTI-USER FEATURE
// Random shares of the key for first N-1 users
std::vector<std::vector<int32_t>> splitKey(const std::vector<int32_t>& master, int numUsers) {
    int dim = master.size();
    std::vector<std::vector<int32_t>> shares(numUsers, std::vector<int32_t>(dim, 0));

    for (int i = 0; i < numUsers - 1; i++)
        for (int j = 0; j < dim; j++)
            shares[i][j] = std::uniform_int_distribution<int32_t>(0, 1)(rng);

    // Last share absorbs remainder so all shares sum to master
    for (int j = 0; j < dim; j++) {
        int sum = 0;
        for (int i = 0; i < numUsers - 1; i++) sum += shares[i][j];
        shares[numUsers - 1][j] = master[j] - sum;
    }
    return shares;
}
 
// Summing all results reconstructs the full key binding.
// Subtracting from hiddenValue recovers the original bit.
int combinePartials(const Ciphertext& ct,
                    const std::vector<std::vector<int32_t>>& shares) {
    Torus fullBinding = 0;
    for (const auto& s : shares)
        fullBinding += dotProduct(ct.randomMask, s);
    return decodeBit(ct.hiddenValue - fullBinding);
}
 
// MAIN FUNCTION 
int main() {

    // Parameters
    const int    KEY_DIMENSION = 16;
    const double NOISE_STDDEV  = 1.0 / (1 << 10);
    const double NOISE_MULTI   = 1.0 / (1 << 13);
    const int INPUT[4] = {0,1,0,0};
 
    // Key generation
    std::cout << "INPUT: [ ";
    for (int b : INPUT) std::cout << b << " ";
    std::cout << "]\n";

    auto key = generateKey(KEY_DIMENSION);
    std::cout << "SECRET KEY: [ ";
    for (int b : key) std::cout << b << " ";
    std::cout << "]\n";
    std::cout << std::string(50, '-') << "\n\n";
 
    // Encrypt / Decrypt 
    std::cout << "ENCRYPT -> DECRYPT\n";
    for (int bit : INPUT) {
        std::cout << "  bit " << bit << "\n";
        std::cout << "    encrypt: ";
        Ciphertext ct = encrypt(bit, key, NOISE_STDDEV);
        std::cout << "    decrypt: ";
        int recovered = decrypt(ct, key);
        std::cout << "    " << bit << " -> " << recovered
                  << (recovered == bit ? "  PASS" : "  FAIL") << "\n\n";
    }
    std::cout << std::string(50, '-') << "\n\n";
 
    // Homomorphic NAND 
    std::cout << "HOMOMORPHIC NAND GATE\n"; 
    for (int x : {0, 1}) {
        for (int y : {0, 1}) {
            int expected = !(x & y);
            std::cout << "  NAND(" << x << ", " << y << ")  ->  expected: " << expected << "\n";
 
            std::cout << "    encrypt x=" << x << ": ";
            Ciphertext encX = encrypt(x, key, NOISE_STDDEV);
 
            std::cout << "    encrypt y=" << y << ": ";
            Ciphertext encY = encrypt(y, key, NOISE_STDDEV);
 
            Ciphertext result = homNAND(encX, encY);
 
            std::cout << "    decrypt result: ";
            int got = decrypt(result, key);
            std::cout << "    answer: " << got
                      << (got == expected ? "  PASS" : "  FAIL") << "\n\n";
        }
    }
    std::cout << std::string(50, '-') << "\n\n";
 
    // Multi-user decryption
    const int NUM_USERS = 3;
    std::cout << "MULTI-USER DECRYPTION  (" << NUM_USERS << " users)\n";
 
    auto shares = splitKey(key, NUM_USERS);
    for (int i = 0; i < NUM_USERS; i++) {
        std::cout << "  user" << (i+1) << ": [";
        for (int b : shares[i]) std::cout << b << " ";
        std::cout << "]\n";
    }
 
    std::cout << "\n  Encrypting bit 1...\n";
    std::cout << "    encrypt: ";
    Ciphertext multiCt = encrypt(1, key, NOISE_MULTI);
 
    std::cout << "\n  All " << NUM_USERS << " users contribute their share:\n";
    int full = combinePartials(multiCt, shares);
    std::cout << "    decrypted bit: " << full
              << (full == 1 ? "  PASS\n" : "  FAIL\n");
              
    return 0;
}