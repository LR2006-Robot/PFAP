#ifndef POSEIDON_HPP_
#define POSEIDON_HPP_

#include "poseidon_params.hpp"
#include "uint256.h"

// Native (out-of-circuit) Poseidon hash over the alt_bn128 scalar field Fr.
// Shares the exact same constants as the in-circuit gadget (poseidon_gadget.tcc),
// guaranteeing native/circuit agreement.

namespace poseidon {

// Poseidon permutation on a state of t field elements (in place).
inline void poseidon_permutation(std::vector<FieldT>& state) {
    const PoseidonConstants& C = get_poseidon_constants();
    const size_t t = POSEIDON_T;
    const size_t RF = POSEIDON_FULL_ROUNDS;
    const size_t RP = POSEIDON_PARTIAL_ROUNDS;
    const size_t half_full = RF / 2;

    auto sbox = [](const FieldT& x) -> FieldT {
        // x^5
        FieldT x2 = x.squared();
        FieldT x4 = x2.squared();
        return x4 * x;
    };

    auto add_round_constants = [&](size_t round) {
        for (size_t i = 0; i < t; i++) state[i] = state[i] + C.ark[round][i];
    };

    auto mix = [&]() {
        std::vector<FieldT> out(t, FieldT::zero());
        for (size_t i = 0; i < t; i++) {
            FieldT acc = FieldT::zero();
            for (size_t j = 0; j < t; j++) {
                acc = acc + C.mds[i][j] * state[j];
            }
            out[i] = acc;
        }
        state = out;
    };

    size_t round = 0;

    // First half of full rounds.
    for (size_t r = 0; r < half_full; r++, round++) {
        add_round_constants(round);
        for (size_t i = 0; i < t; i++) state[i] = sbox(state[i]);
        mix();
    }

    // Partial rounds (S-box only on the first element).
    for (size_t r = 0; r < RP; r++, round++) {
        add_round_constants(round);
        state[0] = sbox(state[0]);
        mix();
    }

    // Second half of full rounds.
    for (size_t r = 0; r < half_full; r++, round++) {
        add_round_constants(round);
        for (size_t i = 0; i < t; i++) state[i] = sbox(state[i]);
        mix();
    }
}

// 2-to-1 hash: H(left, right). State is [capacity=0, left, right]; output is
// state[0] after one permutation. (t = 3.)
inline FieldT poseidon_hash2(const FieldT& left, const FieldT& right) {
    std::vector<FieldT> state(POSEIDON_T, FieldT::zero());
    // capacity element stays 0; absorb two inputs.
    state[0] = FieldT::zero();
    state[1] = left;
    state[2] = right;
    poseidon_permutation(state);
    return state[0];
}

// 1-to-1 hash: H(x). Used to derive path = Poseidon(cmt). State is [0, x, 0].
inline FieldT poseidon_hash1(const FieldT& x) {
    std::vector<FieldT> state(POSEIDON_T, FieldT::zero());
    state[0] = FieldT::zero();
    state[1] = x;
    state[2] = FieldT::zero();
    poseidon_permutation(state);
    return state[0];
}

// ---------------------------------------------------------------------------
// uint256 <-> field conversions
// ---------------------------------------------------------------------------

// Build a field element exactly from a uint64.
inline FieldT field_from_uint64(uint64_t v) {
    FieldT result = FieldT::zero();
    FieldT base = FieldT(1);
    FieldT two = FieldT(2);
    for (int i = 0; i < 64; i++) {
        if ((v >> i) & 1ULL) result = result + base;
        base = base * two;
    }
    return result;
}

// Interpret a uint256 (bitcoin-style, little-endian bytes in memory: begin()
// is the least significant byte) as a field element. The value is reduced
// modulo the field order via Horner evaluation in the field, so any 256-bit
// input is accepted (no out-of-range bigint construction).
inline FieldT field_from_uint256(const uint256& x) {
    // Extract 4 little-endian 64-bit limbs.
    const unsigned char* p = x.begin();
    uint64_t limbs[4] = {0, 0, 0, 0};
    for (size_t limb = 0; limb < 4; limb++) {
        uint64_t v = 0;
        for (size_t byte = 0; byte < 8; byte++) {
            v |= (uint64_t)p[limb * 8 + byte] << (8 * byte);
        }
        limbs[limb] = v;
    }

    // twoTo64 = 2^64 in the field.
    FieldT twoTo64 = FieldT(1);
    {
        FieldT two = FieldT(2);
        for (int i = 0; i < 64; i++) twoTo64 = twoTo64 * two;
    }

    FieldT result = FieldT::zero();
    FieldT base = FieldT(1);
    for (size_t limb = 0; limb < 4; limb++) {
        result = result + field_from_uint64(limbs[limb]) * base;
        base = base * twoTo64;
    }
    return result;
}

// Convert a field element to a uint256 (little-endian bytes).
inline uint256 uint256_from_field(const FieldT& f) {
    libff::bigint<libff::alt_bn128_r_limbs> b = f.as_bigint();
    std::vector<unsigned char> bytes(32, 0);
    for (size_t limb = 0; limb < 4 && limb < libff::alt_bn128_r_limbs; limb++) {
        uint64_t v = b.data[limb];
        for (size_t byte = 0; byte < 8; byte++) {
            bytes[limb * 8 + byte] = (unsigned char)((v >> (8 * byte)) & 0xFF);
        }
    }
    uint256 out;
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

// ---------------------------------------------------------------------------
// CANONICAL digest-bit conversion (used to bind a SHA-256 commitment digest to
// a field element identically in native code and in-circuit).
//
// The 256-bit commitment digest is represented as a bool vector exactly like
// uint256_to_bool_vector(cmt): bit[i*8 + j] = (byte_i >> (7-j)) & 1, byte 0
// first, MSB-first within each byte. We interpret the vector big-endian (bit 0
// = most significant), matching libsnark's
// pb_variable_array::get_field_element_from_bits (which reads index 0 as MSB).
//
// IMPORTANT: the SMT key path = Poseidon(field_from_bits256(digest_bits)).
// The circuit derives the same field element from the cmtA_old digest bits, so
// native and circuit agree.
// ---------------------------------------------------------------------------
inline FieldT field_from_bits256(const std::vector<bool>& bits) {
    // bits.size() expected 256; interpret bit[0] as MSB.
    FieldT result = FieldT::zero();
    FieldT two = FieldT(2);
    for (size_t i = 0; i < bits.size(); i++) {
        result = result * two;
        if (bits[i]) result = result + FieldT::one();
    }
    return result;
}

// Convert a uint256 to the canonical digest-bit vector:
// bit[i*8 + j] = (byte_i >> (7-j)) & 1, byte 0 first.
inline std::vector<bool> uint256_to_bits256(const uint256& x) {
    std::vector<bool> bits(256, false);
    const unsigned char* p = x.begin();
    for (size_t i = 0; i < 32; i++) {
        unsigned char c = p[i];
        for (size_t j = 0; j < 8; j++) {
            bits[i * 8 + j] = ((c >> (7 - j)) & 1) != 0;
        }
    }
    return bits;
}

// Canonical field element bound to a commitment digest (used as the SMT key
// input): field_from_bits256(uint256_to_bits256(cmt)).
inline FieldT field_from_cmt(const uint256& cmt) {
    return field_from_bits256(uint256_to_bits256(cmt));
}

// Pack a 256-bit big-endian bit vector (bit[0] = MSB) back into a uint256 using
// the same byte/bit convention as uint256_to_bits256:
//   byte_i bit (7-j) = bits[i*8 + j].
inline uint256 bits256_to_uint256(const std::vector<bool>& bits) {
    uint256 out;
    unsigned char* p = out.begin();
    for (size_t i = 0; i < 32; i++) {
        unsigned char c = 0;
        for (size_t j = 0; j < 8; j++) {
            if (bits[i * 8 + j]) c |= (unsigned char)(1u << (7 - j));
        }
        p[i] = c;
    }
    return out;
}

// Serialize a field element to a uint256 using the canonical big-endian
// 256-bit representation. This is the representation used for the SMT root rt
// passed to/from the circuit; it round-trips with field_from_cmt:
//   field_from_cmt(field_to_uint256_be(f)) == f   for any f < p.
inline uint256 field_to_uint256_be(const FieldT& f) {
    libff::bigint<libff::alt_bn128_r_limbs> b = f.as_bigint();
    std::vector<bool> bits(256, false);
    for (size_t i = 0; i < 256; i++) {
        size_t bitpos = 255 - i;
        size_t limb = bitpos / 64;
        size_t off = bitpos % 64;
        bool v = false;
        if (limb < 4) v = ((b.data[limb] >> off) & 1ULL) != 0;
        bits[i] = v;
    }
    return bits256_to_uint256(bits);
}

} // namespace poseidon

#endif // POSEIDON_HPP_
