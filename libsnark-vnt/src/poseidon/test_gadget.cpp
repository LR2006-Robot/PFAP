#include <stdio.h>
#include <iostream>
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"
#include "uint256.h"
#include "poseidon.hpp"
#include "poseidon_gadget.tcc"

using namespace poseidon;
using namespace libsnark;
using namespace std;

typedef libff::Fr<libff::alt_bn128_pp> FieldT;

int main() {
    libff::alt_bn128_pp::init_public_params();

    FieldT a = field_from_uint64(7);
    FieldT b = field_from_uint64(99);
    FieldT native = poseidon_hash2(a, b);

    // Circuit
    protoboard<FieldT> pb;
    pb_variable<FieldT> left, right, out;
    left.allocate(pb, "left");
    right.allocate(pb, "right");
    out.allocate(pb, "out");

    pb_linear_combination<FieldT> llc, rlc;
    llc.assign(pb, left);
    rlc.assign(pb, right);

    poseidon_hash2_gadget<FieldT> g(pb, llc, rlc, out, "h2");
    g.generate_r1cs_constraints();

    pb.val(left) = a;
    pb.val(right) = b;
    g.generate_r1cs_witness();

    FieldT circuit_out = pb.val(out);

    cout << "native  : "; native.as_bigint().print();
    cout << "circuit : "; circuit_out.as_bigint().print();
    cout << "match   : " << (native == circuit_out ? "YES" : "NO") << endl;
    cout << "satisfied: " << (pb.is_satisfied() ? "YES" : "NO") << endl;
    cout << "num_constraints: " << pb.num_constraints() << endl;

    // hash1 test
    {
        FieldT x = field_from_uint64(123456789);
        FieldT n1 = poseidon_hash1(x);
        protoboard<FieldT> pb2;
        pb_variable<FieldT> xv, o2;
        xv.allocate(pb2, "x");
        o2.allocate(pb2, "o");
        pb_linear_combination<FieldT> xlc;
        xlc.assign(pb2, xv);
        poseidon_hash1_gadget<FieldT> g1(pb2, xlc, o2, "h1");
        g1.generate_r1cs_constraints();
        pb2.val(xv) = x;
        g1.generate_r1cs_witness();
        cout << "hash1 match: " << (n1 == pb2.val(o2) ? "YES" : "NO")
             << " satisfied: " << (pb2.is_satisfied() ? "YES" : "NO") << endl;
    }

    return 0;
}
