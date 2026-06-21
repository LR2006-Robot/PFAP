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
#include "poseidon_smt_gadget.tcc"

using namespace poseidon;
using namespace libsnark;
using namespace std;

typedef libff::Fr<libff::alt_bn128_pp> FieldT;

int main() {
    libff::alt_bn128_pp::init_public_params();

    PoseidonSMT tree;
    uint256 cmtA = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    uint256 cmtB = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");

    tree.insert(cmtA);
    tree.insert(cmtB);

    PoseidonSMT::Proof pr = tree.prove(cmtA);
    cout << "found cmtA: " << (pr.found ? "YES" : "NO") << endl;
    cout << "root: " << pr.root.ToString() << endl;
    cout << "path: " << pr.path.ToString() << endl;

    // Build circuit
    protoboard<FieldT> pb;
    pb_variable<FieldT> leaf, root;
    leaf.allocate(pb, "leaf");
    root.allocate(pb, "root");
    pb_variable_array<FieldT> path_bits, siblings;
    path_bits.allocate(pb, 256, "path_bits");
    siblings.allocate(pb, 256, "siblings");

    poseidon_smt_gadget<FieldT> g(pb, leaf, path_bits, siblings, root, "smt");
    g.generate_r1cs_constraints();

    // Witness
    pb.val(leaf) = FieldT::one();
    for (size_t i = 0; i < 256; i++) {
        pb.val(path_bits[i]) = pr.path_bits[i] ? FieldT::one() : FieldT::zero();
        pb.val(siblings[i]) = field_from_uint256(pr.siblings[i]);
    }
    g.generate_r1cs_witness();

    FieldT circuit_root = pb.val(root);
    FieldT native_root = field_from_uint256(pr.root);

    cout << "circuit root matches native: "
         << (circuit_root == native_root ? "YES" : "NO") << endl;
    cout << "satisfied: " << (pb.is_satisfied() ? "YES" : "NO") << endl;
    cout << "num_constraints: " << pb.num_constraints() << endl;

    // Negative test: wrong leaf (prove non-membership of unset cmt should NOT match root with leaf=1)
    uint256 cmtC = uint256S("0x3333333333333333333333333333333333333333333333333333333333333333");
    PoseidonSMT::Proof prC = tree.prove(cmtC);
    cout << "found cmtC (should be NO): " << (prC.found ? "YES" : "NO") << endl;

    return 0;
}
