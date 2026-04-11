//
// Created by zfuser on 4/10/26.
//

#include <vector>
#include <iostream>
#include <random>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

typedef __uint64_t uint64;

class BigInt {
    std::vector<uint64> bits;

    public:
    BigInt(int bitlength) : bits(bitlength/64) {

    }

    ~BigInt() {

    }

    static BigInt random(const int bitlength) {
        BigInt result = BigInt(bitlength);

        std::random_device rd;
        std::mt19937_64 gen64(rd());
        std::uniform_int_distribution<unsigned long long> dis(0, 0xFFFFFFFFFFFFFFFFULL);

        for (unsigned long & bit : result.bits) {
            bit = dis(gen64);
        }
        return result;
    }

    static BigInt testValues(const int bitlength, uint64 value) {
        BigInt result = BigInt(bitlength);

        result.bits[0] = value;
        return result;
    }

    void trim() {
        for (int i = bits.size() -1; i>=0; i--) {
            if (bits[i] == 0) {
                bits.pop_back();
            } else {
                break;
            }
        }
    }

     void operator+(BigInt const& b) {
        int carry = 0;
        for (int i = 0; i<bits.size(); i++) {
            uint64 a_val = (i < bits.size()) ? bits[i] : 0;
            uint64 b_val = (i < b.bits.size()) ? b.bits[i] : 0;

            uint64 sum = a_val + b_val + carry;

            // Detect carry
            if (sum < a_val || (carry && sum == a_val))
                carry = 1;
            else
                carry = 0;

            bits[i] = sum;
        }

        if (carry == 1) {
            bits.push_back(carry);
        }

    }

    bool operator=(BigInt const& b) {

        bool result = true;
        for (int i = 0; i<bits.size(); i++) {
            if (bits[i] != b.bits[i]) {
                result = false;
            }
        }

        return result;
    }

    void operator*(BigInt const& b) {
        BigInt result((bits.size() + b.bits.size()) * 64);

        for (size_t i = 0; i < bits.size(); i++) {
            __uint128_t carry = 0;

            for (size_t j = 0; j < b.bits.size(); j++) {
                __uint128_t prod =( (__uint128_t)bits[i] * (__uint128_t)b.bits[j] ) +
                    result.bits[i + j] +
                    carry;

                result.bits[i + j] = (uint64_t)prod;   // lower 64 bits
                carry = prod >> 64;                   // upper 64 bits
            }

            result.bits[i + b.bits.size()] += (uint64_t)carry;
        }

        result.trim();
        bits = result.bits;
    }

    std::string to_string() const {
        if (bits.empty()) return "0";

        std::ostringstream oss;
        oss << std::hex << std::nouppercase;

        bool started = false;

        for (int i = bits.size() - 1; i >= 0; --i) {
            uint64 part = bits[i];

            if (!started) {
                if (part == 0) continue;

                // First non-zero limb: no padding
                oss << part;
                started = true;
            } else {
                // Remaining limbs: always 16 hex digits (64 bits)
                oss << std::setw(16) << std::setfill('0') << part;
            }
        }

        if (!started) return "0"; // all-zero case

        return oss.str();
    }
};


int main() {
    BigInt a = BigInt::random(512);
    BigInt b = BigInt::testValues(512, 5);
    BigInt c = BigInt::testValues(512, 3);

    std::cout << "Starting Values: "<< std::endl;
    std::cout << a.to_string() << std::endl;
    std::cout << b.to_string() << std::endl;
    std::cout << c.to_string() << std::endl;


    c.operator+(b);
    std::cout << "\nAddition: of 5 + 3 = " << c.to_string() << std::endl;


    c.operator*(b);
    std::cout << "\nMultiplication: of 8 * 5 = " << c.to_string() << std::endl;

    BigInt t = BigInt::testValues(512, 5);

    t.operator+(t);
    t.operator+(t);
    std::cout << "\n ==================================================================\n"
        << t.to_string() << std::endl;


    // mut to add verification
    BigInt e = BigInt::testValues(512, 5000000000000000000);
    BigInt f = BigInt::testValues(512, 5000000000000000000);

    std::cout << "Mult&Add Verification: "<< std::endl;
    std::cout << e.to_string() << std::endl;
    std::cout << f.to_string() << std::endl;

    for (int i = 0; i < 100; ++i) {
        e.operator+(e);
    }

    std::cout << "\n ==================================================================\n"
        << e.to_string() << std::endl;

    f.operator*(BigInt::testValues(512, 1024^10));
    std::cout << f.to_string() << std::endl;
}