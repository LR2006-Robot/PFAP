#include <stdio.h>
#include <iostream>
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"
#include "uint256.h"
#include "poseidon.hpp"

using namespace poseidon;
using namespace std;

int main() {
    libff::alt_bn128_pp::init_public_params();

    FieldT a = field_from_uint64(1);
    FieldT b = field_from_uint64(2);
    FieldT h = poseidon_hash2(a, b);
    cout << "poseidon_hash2(1,2) bigint: ";
    h.as_bigint().print();

    FieldT h1 = poseidon_hash1(field_from_uint64(123456789));
    cout << "poseidon_hash1(123456789) bigint: ";
    h1.as_bigint().print();

    // round trip uint256
    uint256 u = uint256S("0x0000000000000000000000000000000000000000000000000000000000000abc");
    FieldT fu = field_from_uint256(u);
    uint256 back = uint256_from_field(fu);
    cout << "roundtrip uint256: " << back.ToString() << endl;

    // determinism check
    FieldT h_again = poseidon_hash2(a, b);
    cout << "deterministic: " << (h == h_again ? "YES" : "NO") << endl;

    cout << "constants R_F=" << POSEIDON_FULL_ROUNDS
         << " R_P=" << POSEIDON_PARTIAL_ROUNDS
         << " t=" << POSEIDON_T << endl;
    return 0;
}
