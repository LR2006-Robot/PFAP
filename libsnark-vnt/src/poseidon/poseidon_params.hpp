#ifndef POSEIDON_PARAMS_HPP_
#define POSEIDON_PARAMS_HPP_

#include <vector>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

// Poseidon hash parameters for the alt_bn128 (BN254) scalar field Fr.
//
// We use a 2-to-1 sponge configuration:
//   t       = 3   (rate 2, capacity 1)  -> hashes two field elements into one
//   alpha   = 5   (S-box x^5; gcd(5, p-1) = 1 for BN254 Fr)
//   R_F     = 8   (full rounds)
//   R_P     = 57  (partial rounds)
//
// Round constants (ARK) and the MDS matrix are generated deterministically
// from the Grain LFSR construction described in the Poseidon paper / EIP-2494,
// so the native implementation and the libsnark gadget share *exactly* the
// same constants (the same generator code is used by both).
//
// IMPORTANT: any change to these parameters or to the constant-generation
// procedure invalidates all previously generated proofs and proving/verifying
// keys.

namespace poseidon {

typedef libff::Fr<libff::alt_bn128_pp> FieldT;

static const size_t POSEIDON_T = 3;
static const size_t POSEIDON_ALPHA = 5;
static const size_t POSEIDON_FULL_ROUNDS = 8;
static const size_t POSEIDON_PARTIAL_ROUNDS = 57;

// Holds the generated constants. Generated once and cached.
struct PoseidonConstants {
    // ark[round][i], round in [0, R_F + R_P), i in [0, t)
    std::vector<std::vector<FieldT>> ark;
    // mds[i][j], i,j in [0, t)
    std::vector<std::vector<FieldT>> mds;
    bool initialized = false;
};

// ---------------------------------------------------------------------------
// Grain LFSR bit generator (as specified for Poseidon parameter generation).
// ---------------------------------------------------------------------------
class GrainLFSR {
public:
    GrainLFSR(size_t field_size_bits, size_t t, size_t r_f, size_t r_p)
        : state_(80, false), head_(0)
    {
        // Initialize the 80-bit state per the Poseidon spec.
        // b0..b1   : field type (0b01 = prime field)
        // b2..b5   : S-box type (4-bit field; value 0 selects exponent x^alpha)
        // b6..b17  : field size in bits
        // b18..b29 : number of S-boxes (t)
        // b30..b39 : R_F (full rounds)
        // b40..b49 : R_P (partial rounds)
        // b50..b79 : all ones
        std::vector<bool> init;
        // field: prime field -> 0b01
        appendBits(init, 1, 2);
        // sbox: 0b00000 -> exponent x^alpha
        appendBits(init, 0, 4);
        appendBits(init, field_size_bits, 12);
        appendBits(init, t, 12);
        appendBits(init, r_f, 10);
        appendBits(init, r_p, 10);
        appendBits(init, (1u << 30) - 1, 30); // 30 ones
        // init is 80 bits
        for (size_t i = 0; i < 80; i++) state_[i] = init[i];

        // Discard the first 160 bits.
        for (size_t i = 0; i < 160; i++) nextBitRaw();
    }

    // Returns the next raw output bit of the Grain LFSR stream. The canonical
    // Poseidon "double-bit / discard rejected" filtering is applied in
    // grainNextFieldElement (not here).
    bool nextBit() { return nextBitRaw(); }

private:
    static void appendBits(std::vector<bool>& v, uint64_t value, size_t nbits) {
        for (size_t i = 0; i < nbits; i++) {
            v.push_back(((value >> (nbits - 1 - i)) & 1ULL) != 0);
        }
    }

    bool nextBitRaw() {
        // Grain-like 80-bit LFSR feedback (taps as in the Poseidon reference).
        bool b = state_[(head_ + 62) % 80] ^ state_[(head_ + 51) % 80]
               ^ state_[(head_ + 38) % 80] ^ state_[(head_ + 23) % 80]
               ^ state_[(head_ + 13) % 80] ^ state_[head_];
        bool out = state_[head_];
        state_[head_] = b;
        head_ = (head_ + 1) % 80;
        return out;
    }

    std::vector<bool> state_;
    size_t head_;
};

inline void shiftLeftOne(libff::bigint<libff::alt_bn128_r_limbs>& x);
inline bool lessThanModulus(const libff::bigint<libff::alt_bn128_r_limbs>& x);

// Build a field element from the LFSR using rejection sampling: read
// field_size_bits bits as a big-endian integer; if >= modulus, reject and
// retry. Uses the "double-bit" filtering rule of the Poseidon spec.
inline FieldT grainNextFieldElement(GrainLFSR& lfsr, size_t field_size_bits) {
    while (true) {
        libff::bigint<libff::alt_bn128_r_limbs> acc;
        for (size_t i = 0; i < libff::alt_bn128_r_limbs; i++) acc.data[i] = 0;

        size_t got = 0;
        while (got < field_size_bits) {
            // double-bit rule: read a bit; if it is 1, the *next* bit is used,
            // otherwise the next bit is discarded.
            bool sel = lfsr.nextBit();
            bool val = lfsr.nextBit();
            if (sel) {
                // shift acc left by 1 and OR in val
                shiftLeftOne(acc);
                if (val) acc.data[0] |= 1ULL;
                got++;
            }
            // if sel == 0, discard val and continue
        }

        // Reject if acc >= modulus.
        if (lessThanModulus(acc)) {
            FieldT f = FieldT(acc);
            return f;
        }
        // else retry
    }
}

inline void shiftLeftOne(libff::bigint<libff::alt_bn128_r_limbs>& x) {
    const size_t n = libff::alt_bn128_r_limbs;
    uint64_t carry = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t newcarry = (x.data[i] >> 63) & 1ULL;
        x.data[i] = (x.data[i] << 1) | carry;
        carry = newcarry;
    }
}

inline bool lessThanModulus(const libff::bigint<libff::alt_bn128_r_limbs>& x) {
    const auto& m = FieldT::mod;
    const size_t n = libff::alt_bn128_r_limbs;
    for (size_t i = n; i-- > 0;) {
        if (x.data[i] < m.data[i]) return true;
        if (x.data[i] > m.data[i]) return false;
    }
    return false; // equal -> not less than
}

// Generate (and cache) the Poseidon constants.
inline const PoseidonConstants& get_poseidon_constants() {
    static PoseidonConstants C;
    if (C.initialized) return C;

    const size_t t = POSEIDON_T;
    const size_t rounds = POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS;
    // BN254 Fr is 254 bits.
    const size_t field_size_bits = 254;

    GrainLFSR lfsr(field_size_bits, t, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS);

    // Round constants: rounds * t elements.
    C.ark.resize(rounds, std::vector<FieldT>(t));
    for (size_t r = 0; r < rounds; r++) {
        for (size_t i = 0; i < t; i++) {
            C.ark[r][i] = grainNextFieldElement(lfsr, field_size_bits);
        }
    }

    // MDS matrix via a Cauchy matrix: x_i = i, y_j = t + j (all distinct),
    // mds[i][j] = 1 / (x_i + y_j). This is a standard MDS construction and is
    // deterministic, matching between native and circuit.
    C.mds.resize(t, std::vector<FieldT>(t));
    std::vector<FieldT> xs(t), ys(t);
    for (size_t i = 0; i < t; i++) xs[i] = FieldT(i);
    for (size_t j = 0; j < t; j++) ys[j] = FieldT(t + j);
    for (size_t i = 0; i < t; i++) {
        for (size_t j = 0; j < t; j++) {
            C.mds[i][j] = (xs[i] + ys[j]).inverse();
        }
    }

    C.initialized = true;
    return C;
}

} // namespace poseidon

#endif // POSEIDON_PARAMS_HPP_
