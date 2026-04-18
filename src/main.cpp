/*
   Final Project - CDA5106 Spring 2026
   Extending the TFHE (Torus Fast-Fully Homomorphic Encryption) for Multi-User Access
*/
#include <iostream>
#include <vector>
#include <cstdint>
#include <cmath>
#include <random>
#include <iomanip>
#include <string>
#include <sstream>
 
/*
======================= Torus Fast-Fully Homomorphic Encryption Simulator =======================
*/

using Torus = int32_t;
// Fixed seed for reproducible runs
std::mt19937 rng(10);

// RandomMask - public random vector, one Torus value per key bit
// HiddenValue - the message locked behind the key: <mask,key> + msg + noise
struct Ciphertext {
	std::vector<Torus> randomMask;
	Torus hiddenValue;
};

// Takes in a decimal value in [0, 1) and returns the equivalent Torus integer.
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
 
// Input:  bit: plaintext bit to hide (0 or 1) , key: secret key used to lock the message
//         noiseLevel: Gaussian noise std-dev
// Output: Ciphertext (randomMask[], hiddenValue)
Ciphertext encrypt(int bit, const std::vector<int32_t>& key, double noiseLevel) {
	Ciphertext ct;
	ct.randomMask.resize(key.size());
	for (auto& v : ct.randomMask) v = std::uniform_int_distribution<int32_t>(INT32_MIN, INT32_MAX)(rng);

	Torus keyBinding = dotProduct(ct.randomMask, key);
	Torus encodedBit = encodeBit(bit);
	Torus securityNoise = smallNoise(noiseLevel);

	// Formula: hiddenValue = <randomMask, key> + encodeBit(bit) + noise
	ct.hiddenValue = keyBinding + encodedBit + securityNoise;
 
	std::cout << "         bit " << bit << " -> [torus] " << tstr(encodedBit) << "  +  [binding] " << tstr(keyBinding) << "  +  [noise] " << tstr(securityNoise) << "  =  [hidden] " << tstr(ct.hiddenValue) << "\n";
 
	return ct;
}
 
// Input: ct: Ciphertext from encrypt(), key: the same secret key used during encryption
// Output: the original plaintext bit (0 or 1)
int decrypt(const Ciphertext& ct, const std::vector<int32_t>& key) {
	// Formula: strip binding -> encodedBit + noise -> round to nearest
	Torus keyBinding = dotProduct(ct.randomMask, key);
	Torus encodedPlusNoise = ct.hiddenValue - keyBinding;
	int result = decodeBit(encodedPlusNoise);
 
	std::cout << "         [hidden] " << tstr(ct.hiddenValue) << "  -  [binding] " << tstr(keyBinding) << "  =  " << tstr(encodedPlusNoise) << "  ->  bit = " << result << "\n";
 
	return result;
}
 
// Input: ct1: Ciphertext encrypting bit x, ct2: Ciphertext encrypting bit y
// Output: Ciphertext encrypting NAND(x, y)
Ciphertext homNAND(const Ciphertext& ct1, const Ciphertext& ct2) {
	Ciphertext output;
	output.randomMask.resize(ct1.randomMask.size());
	for (int i = 0; i < (int)ct1.randomMask.size(); i++)
		output.randomMask[i] = -ct1.randomMask[i] - ct2.randomMask[i];

	// Formula: output = (5/8) - ct1 - ct2
	output.hiddenValue = toTorus(5.0 / 8.0) - ct1.hiddenValue - ct2.hiddenValue;
 
	return output;
}
 
/*
======================= Multi-User Access Extension (Shamir's Secret Sharing) =======================
*/

// (x, y) point on the secret polynomial - one share per user
struct Share {
	int64_t x;
	int64_t y;
};

// Input: a: inverse number, p: prime  
// Output: a^-1 mod p 
static int64_t modInverse(int64_t a, int64_t p) {
	int64_t t = 0, newT = 1;
	int64_t r = p, newR = a;
	while (newR != 0) {
		int64_t q = r / newR;
		int64_t tmpT = t - q * newT;  t = newT;  newT = tmpT;
		int64_t tmpR = r - q * newR;  r = newR;  newR = tmpR;
	}
	if (r != 1) throw std::runtime_error("No inverse");
	return t < 0 ? t + p : t;
}

// Input: secret: integer to protect, N: total number of shares,
//        prime: prime modulus 
// Output: N shares
std::vector<Share> shamirSplit(int64_t secret, int N, int64_t prime) {
	std::uniform_int_distribution<int64_t> dist(1, prime - 1);
	int64_t a = dist(rng);

	std::vector<Share> shares;
	for (int i = 1; i <= N; i++) {
		int64_t x = i;
		int64_t y = (secret + a * x) % prime;
		std::cout << "\t\tUser " << i << ": f(" << x << ") = ("<< secret << " + " << a << "*" << x << ") % " << prime << " = " << y << " = (" << x << "," << y << ")" <<"\n";
		shares.push_back({x, y});
	}
	return shares;
}

// Input: s1, s2: any two shares with their original x-coordinates
//        prime: same modulus used during split
// Output: the reconstructed secret f(0) via Lagrange interpolation.
int64_t shamirReconstruct(const Share& s1, const Share& s2, int64_t prime) {
	int64_t x1 = s1.x, y1 = s1.y;
	int64_t x2 = s2.x, y2 = s2.y;

	int64_t inv1 = modInverse((x1 - x2 + prime) % prime, prime);
	int64_t inv2 = modInverse((x2 - x1 + prime) % prime, prime);
	int64_t term1 = (y1 * ((prime - x2) % prime) % prime) * inv1 % prime;
	int64_t term2 = (y2 * ((prime - x1) % prime) % prime) * inv2 % prime;
	int64_t result = (term1 + term2) % prime;

	std::cout << "\t\tLagrange: y1*L1 = " << y1 << " * inv(" << x1 << "-" << x2 << ") = " << term1 << ",  y2*L2 = " << y2 << " * inv(" << x2 << "-" << x1 << ") = " << term2 << ",  sum = " << result << "\n";

	return result;
}

// ======================= Main Function =======================
int main() {
	// Parameters
	const int KEY_DIMENSION = 16;
	const double NOISE_STDDEV = 1.0 / (1 << 10);
	const double NOISE_MULTI = 1.0 / (1 << 13);
	const int INPUT[4] = {1,1,0,1};
 
	// Key generation
	std::cout << "INPUT: [ ";
	for (int b : INPUT) std::cout << b << " ";
	std::cout << "]\n";

	auto key = generateKey(KEY_DIMENSION);
	std::cout << "SECRET KEY: [ ";
	for (int b : key) std::cout << b << " ";
	std::cout << "]\n\n";

	// Encrypt / Decrypt
	std::cout << std::string(50, '=') << "\n";
	std::cout << "ENCRYPT -> DECRYPT TEST\n";
	std::cout << std::string(50, '=') << "\n\n";
	int encDecPass = 0, encDecFail = 0;
	for (int bit : INPUT) {
		std::cout << "\tEncrypting bit '" << bit << "':\n";
		std::cout << "\t\tEncryption: ";
		Ciphertext ct = encrypt(bit, key, NOISE_STDDEV);
		std::cout << "\t\tDecryption: ";
		int recovered = decrypt(ct, key);
		bool ok = (recovered == bit);
		std::cout << "\t\t" << bit << " -> " << recovered << (ok ? "  PASS" : "  FAIL") << "\n\n";
		ok ? encDecPass++ : encDecFail++;
	}

	// Homomorphic NAND
	std::cout << std::string(50, '=') << "\n";
	std::cout << "HOMOMORPHIC NAND GATE TEST\n";
	std::cout << std::string(50, '=') << "\n\n";
	int nandPass = 0, nandFail = 0;
	for (int x : {0, 1}) {
		for (int y : {0, 1}) {
			int expected = !(x & y);
			std::cout << "\tNAND(" << x << ", " << y << ")  ->  expected: " << expected << "\n";

			std::cout << "\t\tEncrypt x=" << x << ": ";
			Ciphertext encX = encrypt(x, key, NOISE_STDDEV);

			std::cout << "\t\tEncrypt y=" << y << ": ";
			Ciphertext encY = encrypt(y, key, NOISE_STDDEV);

			Ciphertext result = homNAND(encX, encY);

			std::cout << "\t\tNAND computation:     " << tstr(toTorus(5.0/8.0)) << "  -  [hidden_x] " << tstr(encX.hiddenValue) << "  -  [hidden_y] " << tstr(encY.hiddenValue) << "  =  [result] " << tstr(result.hiddenValue) << "\n";

			std::cout << "\t\tDecrypt result: ";
			int got = decrypt(result, key);
			bool ok = (got == expected);
			std::cout << "\t\tAnswer: " << got << (ok ? "  PASS" : "  FAIL") << "\n\n";
			ok ? nandPass++ : nandFail++;
		}
	}

	// Multi-User Access
	const int64_t SSS_PRIME = 65537;   

	int64_t masterSecret = 0;
	for (int i = 0; i < KEY_DIMENSION; i++)
		masterSecret |= (int64_t)key[i] << i;

	std::cout << std::string(50, '=') << "\n";
	std::cout << "MULTI-USER ACCESS TEST\n";
	std::cout << std::string(50, '=') << "\n\n";
	std::cout << "\tPrime: " << SSS_PRIME << "  Secret: " << masterSecret << "\n\n";

	std::cout << "\tShares:\n";
	auto shares = shamirSplit(masterSecret, 3, SSS_PRIME);
	std::cout << "\n\tReconstruction of Secret Key:\n";
	int multiPass = 0, multiFail = 0;
	const int pairs[3][2] = {{0,1},{0,2},{1,2}};
	for (auto& p : pairs) {
		std::cout << "\t\tUsers (" << (p[0]+1) << "," << (p[1]+1) << "):\n";
		int64_t recovered = shamirReconstruct(shares[p[0]], shares[p[1]], SSS_PRIME);
		bool ok = (recovered == masterSecret);
		std::cout << "\t\tResult: " << recovered << (ok ? "  PASS" : "  FAIL") << "\n\n";
		ok ? multiPass++ : multiFail++;
	}

	std::cout << "\tEnd-to-end (Reconstructing secret from shares 1 & 3):\n";
	{
		int64_t recoSecret = shamirReconstruct(shares[0], shares[2], SSS_PRIME);
		std::cout << "\t\tRecovered secret: " << recoSecret << "\n";
		std::vector<int32_t> recoKey(KEY_DIMENSION);
		for (int i = 0; i < KEY_DIMENSION; i++)
			recoKey[i] = (recoSecret >> i) & 1;

		std::cout << "\t\tOriginal key     : [ "; for (int b : key) std::cout << b << " "; std::cout << "]\n";
		std::cout << "\t\tReconstructed key: [ "; for (int b : recoKey) std::cout << b << " "; std::cout << "]\n\n";
		for (int testBit : {0, 1}) {
			std::cout << "\t\tEncrypt bit: " << testBit;
			Ciphertext ct = encrypt(testBit, key, NOISE_STDDEV);
			std::cout << "\t\tDecrypt bit: " << testBit;
			int got = decrypt(ct, recoKey);
			bool ok = (got == testBit);
			std::cout << "\t\tBit " << testBit << " -> " << got << (ok ? "  PASS" : "  FAIL") << "\n\n";
			ok ? multiPass++ : multiFail++;
		}
	}

return 0;
}