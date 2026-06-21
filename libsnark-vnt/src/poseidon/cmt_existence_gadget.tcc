#ifndef CMT_EXISTENCE_GADGET_TCC_
#define CMT_EXISTENCE_GADGET_TCC_

#include "poseidon_smt_gadget.tcc"
#include "poseidon.hpp"

// Proves that a 256-bit commitment digest `cmt_bits` (a digest_variable's bits,
// in canonical order: index 0 = MSB) has been inserted into the global depth-256
// Poseidon sparse Merkle tree with root `rt`.
//
// Steps (all constrained):
//   1. cmt_field = sum_{i} cmt_bits[i] * 2^(255-i)        (matches field_from_bits256)
//   2. path_field = Poseidon(cmt_field)                    (matches poseidon_hash1)
//   3. path_field decomposed big-endian into path_bits[0..255]
//      (matches PoseidonSMT::field_to_path_bits)
//   4. SMT membership of leaf=1 at path_bits under root rt
//
// The witness (path_bits + siblings) is provided externally (computed natively
// by PoseidonSMT::prove). rt is a public input.

namespace poseidon {

using namespace libsnark;

template<typename FieldTT>
class cmt_existence_gadget : public gadget<FieldTT> {
public:
    pb_variable_array<FieldTT> cmt_bits;     // 256, index 0 = MSB (digest order)
    pb_variable_array<FieldTT> rt_bits;      // 256-bit SMT root (public input), MSB-first

    pb_variable<FieldTT> cmt_field;
    pb_variable<FieldTT> path_field;
    pb_variable<FieldTT> rt_field;           // rt packed into a field element
    std::shared_ptr<poseidon_hash1_gadget<FieldTT>> hash1;

    pb_variable_array<FieldTT> path_bits;    // 256, index 0 = MSB
    pb_variable_array<FieldTT> siblings;     // 256, leaf-first
    pb_variable<FieldTT> leaf_one;
    std::shared_ptr<poseidon_smt_gadget<FieldTT>> smt;

    // Canonicity check: bits representing d = (p-1) - V, proving V <= p-1 (V < p).
    pb_variable_array<FieldTT> diff_bits;    // 254 bits of (p-1 - path_field)

    cmt_existence_gadget(
        protoboard<FieldTT>& pb,
        const pb_variable_array<FieldTT>& cmt_bits_,
        const pb_variable_array<FieldTT>& rt_bits_,
        const std::string& annotation_prefix = "cmt_existence")
        : gadget<FieldTT>(pb, annotation_prefix),
          cmt_bits(cmt_bits_), rt_bits(rt_bits_)
    {
        cmt_field.allocate(pb, FMT(annotation_prefix, "_cmt_field"));
        path_field.allocate(pb, FMT(annotation_prefix, "_path_field"));
        rt_field.allocate(pb, FMT(annotation_prefix, "_rt_field"));
        leaf_one.allocate(pb, FMT(annotation_prefix, "_leaf_one"));
        path_bits.allocate(pb, 256, FMT(annotation_prefix, "_path_bits"));
        siblings.allocate(pb, 256, FMT(annotation_prefix, "_siblings"));
        diff_bits.allocate(pb, 254, FMT(annotation_prefix, "_diff_bits"));

        pb_linear_combination<FieldTT> cf;
        cf.assign(pb, cmt_field);
        hash1.reset(new poseidon_hash1_gadget<FieldTT>(
            pb, cf, path_field, FMT(annotation_prefix, "_h1")));

        smt.reset(new poseidon_smt_gadget<FieldTT>(
            pb, leaf_one, path_bits, siblings, rt_field, FMT(annotation_prefix, "_smt")));
    }

    void generate_r1cs_constraints() {
        // 1. cmt_field == sum cmt_bits[i] * 2^(255-i)
        linear_combination<FieldTT> cmtlc;
        FieldTT coeff = FieldTT::one();
        // build from LSB (index 255) up to MSB (index 0)
        for (size_t k = 0; k < 256; k++) {
            size_t idx = 255 - k; // bit at this weight
            cmtlc = cmtlc + coeff * cmt_bits[idx];
            coeff = coeff + coeff; // *2
        }
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldTT>(cmtlc, 1, cmt_field),
            FMT(this->annotation_prefix, "_cmt_pack"));

        // 1b. rt_field == sum rt_bits[i] * 2^(255-i)  (matches field_to_uint256_be
        // / field_from_bits256). rt_bits are public inputs (boolean enforced by
        // the outer multipacking unpacker).
        linear_combination<FieldTT> rtlc;
        FieldTT crt = FieldTT::one();
        for (size_t k = 0; k < 256; k++) {
            size_t idx = 255 - k;
            rtlc = rtlc + crt * rt_bits[idx];
            crt = crt + crt;
        }
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldTT>(rtlc, 1, rt_field),
            FMT(this->annotation_prefix, "_rt_pack"));

        // 2. path_field = Poseidon(cmt_field)
        hash1->generate_r1cs_constraints();

        // 3. path_bits big-endian decomposition of path_field, each boolean.
        for (size_t i = 0; i < 256; i++) {
            generate_boolean_r1cs_constraint<FieldTT>(this->pb, path_bits[i],
                FMT(this->annotation_prefix, "_pbit_%zu", i));
        }
        linear_combination<FieldTT> pathlc;
        FieldTT c2 = FieldTT::one();
        for (size_t k = 0; k < 256; k++) {
            size_t idx = 255 - k;
            pathlc = pathlc + c2 * path_bits[idx];
            c2 = c2 + c2;
        }
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldTT>(pathlc, 1, path_field),
            FMT(this->annotation_prefix, "_path_decomp"));

        // 3b. Canonicity: enforce the integer V represented by path_bits is < p,
        // so the 256-bit decomposition of path_field is unique (matches native
        // field_to_path_bits). Force the two top weights (2^255, 2^254) to 0 so
        // V < 2^254, then prove V <= p-1 by exhibiting d = (p-1) - V as a
        // genuine 254-bit non-negative integer.
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldTT>(path_bits[0], 1, 0),
            FMT(this->annotation_prefix, "_top0"));
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldTT>(path_bits[1], 1, 0),
            FMT(this->annotation_prefix, "_top1"));

        for (size_t i = 0; i < 254; i++) {
            generate_boolean_r1cs_constraint<FieldTT>(this->pb, diff_bits[i],
                FMT(this->annotation_prefix, "_dbit_%zu", i));
        }
        // diff_lc = sum diff_bits[i] * 2^i  (LSB-first)
        linear_combination<FieldTT> difflc;
        FieldTT cd = FieldTT::one();
        for (size_t i = 0; i < 254; i++) {
            difflc = difflc + cd * diff_bits[i];
            cd = cd + cd;
        }
        // Enforce: path_field + diff == (p-1).  (p-1) == -1 in the field.
        FieldTT p_minus_1 = FieldTT::zero() - FieldTT::one();
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldTT>(
                pb_linear_combination<FieldTT>(path_field) + difflc,
                1,
                p_minus_1),
            FMT(this->annotation_prefix, "_canon"));

        // 4. leaf == 1
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldTT>(leaf_one, 1, 1),
            FMT(this->annotation_prefix, "_leaf1"));

        smt->generate_r1cs_constraints();
    }

    // path_bits_vals and sibling_vals must be supplied by the caller (from the
    // native PoseidonSMT proof). cmt_bits must already be filled by the caller.
    void generate_r1cs_witness(
        const std::vector<bool>& path_bits_vals,
        const std::vector<FieldTT>& sibling_vals)
    {
        // cmt_field
        FieldTT cf = FieldTT::zero();
        for (size_t i = 0; i < 256; i++) {
            cf = cf + cf;
            if (this->pb.val(cmt_bits[i]) == FieldTT::one()) cf = cf + FieldTT::one();
        }
        this->pb.val(cmt_field) = cf;

        // rt_field from rt_bits (caller fills rt_bits before calling this).
        FieldTT rf = FieldTT::zero();
        for (size_t i = 0; i < 256; i++) {
            rf = rf + rf;
            if (this->pb.val(rt_bits[i]) == FieldTT::one()) rf = rf + FieldTT::one();
        }
        this->pb.val(rt_field) = rf;

        hash1->generate_r1cs_witness();

        // path_bits
        for (size_t i = 0; i < 256; i++) {
            this->pb.val(path_bits[i]) = path_bits_vals[i] ? FieldTT::one() : FieldTT::zero();
        }

        // diff_bits = (p-1) - path_field, as a 254-bit non-negative integer.
        {
            FieldTT p_minus_1 = FieldTT::zero() - FieldTT::one();
            FieldTT d = p_minus_1 - this->pb.val(path_field);
            libff::bigint<libff::alt_bn128_r_limbs> db = d.as_bigint();
            for (size_t i = 0; i < 254; i++) {
                size_t limb = i / 64;
                size_t off = i % 64;
                bool bit = false;
                if (limb < 4) bit = ((db.data[limb] >> off) & 1ULL) != 0;
                this->pb.val(diff_bits[i]) = bit ? FieldTT::one() : FieldTT::zero();
            }
        }

        // siblings
        for (size_t i = 0; i < 256; i++) {
            this->pb.val(siblings[i]) = sibling_vals[i];
        }
        this->pb.val(leaf_one) = FieldTT::one();

        smt->generate_r1cs_witness();
    }
};

} // namespace poseidon

#endif // CMT_EXISTENCE_GADGET_TCC_
