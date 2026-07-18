#include <stdio.h>
#include <iostream>
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"
#include "uint256.h"
#include "poseidon.hpp"
#include "poseidon_smt.hpp"
#include "cmt_existence_gadget.tcc"

using namespace poseidon;
using namespace libsnark;
using namespace std;

typedef libff::Fr<libff::alt_bn128_pp> FieldT;

int main() {
    libff::alt_bn128_pp::init_public_params();

    PoseidonSMT tree;
    uint256 cmtA = uint256S("0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    uint256 cmtB = uint256S("0x0fedcba987654321000000000000000000000000000000000000000000000001");
    tree.insert(cmtB);
    tree.insert(cmtA);

    PoseidonSMT::Proof pr = tree.prove(cmtA);
    cout << "found: " << (pr.found ? "YES" : "NO") << "  root=" << pr.root.ToString() << endl;

    protoboard<FieldT> pb;
    pb_variable_array<FieldT> rt_bits;
    rt_bits.allocate(pb, 256, "rt_bits");
    pb_variable_array<FieldT> cmt_bits;
    cmt_bits.allocate(pb, 256, "cmt_bits");

    cmt_existence_gadget<FieldT> g(pb, cmt_bits, rt_bits, "ex");
    g.generate_r1cs_constraints();

    // fill cmt_bits with canonical digest bits of cmtA
    std::vector<bool> cb = uint256_to_bits256(cmtA);
    for (size_t i = 0; i < 256; i++) pb.val(cmt_bits[i]) = cb[i] ? FieldT::one() : FieldT::zero();
    // fill rt_bits with canonical big-endian bits of the native root
    std::vector<bool> rb = uint256_to_bits256(pr.root);
    for (size_t i = 0; i < 256; i++) pb.val(rt_bits[i]) = rb[i] ? FieldT::one() : FieldT::zero();

    std::vector<FieldT> sibs(256);
    for (size_t i = 0; i < 256; i++) sibs[i] = field_from_uint256(pr.siblings[i]);

    g.generate_r1cs_witness(pr.path_bits, sibs);

    FieldT native_root = field_from_cmt(pr.root);
    cout << "circuit rt_field == native root: " << (pb.val(g.rt_field) == native_root ? "YES" : "NO") << endl;
    cout << "satisfied: " << (pb.is_satisfied() ? "YES" : "NO") << endl;
    cout << "num_constraints: " << pb.num_constraints() << endl;

    // Negative test: forge path_bits = canonical + p (i.e. set top bit pattern
    // that still packs to path_field mod p). We construct an alternative 256-bit
    // big-endian representation of (path_field) by adding p to the integer and
    // checking the canonicity constraint rejects it.
    {
        protoboard<FieldT> pb2;
        pb_variable_array<FieldT> rt_bits2;
        rt_bits2.allocate(pb2, 256, "rt_bits2");
        pb_variable_array<FieldT> cmt_bits2;
        cmt_bits2.allocate(pb2, 256, "cmt_bits2");
        cmt_existence_gadget<FieldT> g2(pb2, cmt_bits2, rt_bits2, "ex2");
        g2.generate_r1cs_constraints();
        for (size_t i = 0; i < 256; i++) pb2.val(cmt_bits2[i]) = cb[i] ? FieldT::one() : FieldT::zero();
        for (size_t i = 0; i < 256; i++) pb2.val(rt_bits2[i]) = rb[i] ? FieldT::one() : FieldT::zero();

        std::vector<bool> forged = pr.path_bits;
        // Force top bit (weight 2^255) to 1 -> definitely > p -> must be rejected.
        forged[0] = true;
        g2.generate_r1cs_witness(forged, sibs);
        cout << "forged (top bit set) satisfied (should be NO): "
             << (pb2.is_satisfied() ? "YES" : "NO") << endl;
    }

    // Stronger negative test: exact f+p wrap representation.
    {
        protoboard<FieldT> pb3;
        pb_variable_array<FieldT> rt_bits3;
        rt_bits3.allocate(pb3, 256, "rt_bits3");
        pb_variable_array<FieldT> cmt_bits3;
        cmt_bits3.allocate(pb3, 256, "cmt_bits3");
        cmt_existence_gadget<FieldT> g3(pb3, cmt_bits3, rt_bits3, "ex3");
        g3.generate_r1cs_constraints();
        for (size_t i = 0; i < 256; i++) pb3.val(cmt_bits3[i]) = cb[i] ? FieldT::one() : FieldT::zero();
        for (size_t i = 0; i < 256; i++) pb3.val(rt_bits3[i]) = rb[i] ? FieldT::one() : FieldT::zero();

        // forged_int = path_field_int + p, build big-endian 256-bit vector.
        libff::bigint<libff::alt_bn128_r_limbs> pfb =
            poseidon_hash1(field_from_cmt(cmtA)).as_bigint();
        libff::bigint<libff::alt_bn128_r_limbs> mod = FieldT::mod;
        // add: forged = pfb + mod (manual 5-limb add to avoid overflow)
        unsigned long long limbs[5] = {0,0,0,0,0};
        unsigned long long carry = 0;
        for (int i = 0; i < 4; i++) {
            unsigned long long a = (unsigned long long)pfb.data[i];
            unsigned long long b = (unsigned long long)mod.data[i];
            unsigned long long s = a + b;
            unsigned long long c1 = (s < a) ? 1 : 0;
            unsigned long long s2 = s + carry;
            unsigned long long c2 = (s2 < s) ? 1 : 0;
            limbs[i] = s2;
            carry = c1 + c2;
        }
        limbs[4] = carry;
        std::vector<bool> forged(256, false);
        for (size_t i = 0; i < 256; i++) {
            size_t bitpos = 255 - i;
            size_t limb = bitpos / 64;
            size_t off = bitpos % 64;
            bool v = false;
            if (limb < 5) v = ((limbs[limb] >> off) & 1ULL) != 0;
            forged[i] = v;
        }
        g3.generate_r1cs_witness(forged, sibs);
        cout << "forged (f+p exact wrap) satisfied (should be NO): "
             << (pb3.is_satisfied() ? "YES" : "NO") << endl;
    }

    return 0;
}
