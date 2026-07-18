#ifndef POSEIDON_GADGET_TCC_
#define POSEIDON_GADGET_TCC_

#include "poseidon_params.hpp"

// In-circuit Poseidon gadget over the alt_bn128 scalar field Fr.
// Uses the same constants as the native implementation (poseidon.hpp) via
// poseidon::get_poseidon_constants(), guaranteeing native/circuit agreement.
// Configuration: t = 3, alpha = 5, R_F = 8, R_P = 57.

namespace poseidon {

using namespace libsnark;

template<typename FieldTT>
class poseidon_permutation_gadget : public gadget<FieldTT> {
public:
    size_t t;
    size_t RF;
    size_t RP;

    std::vector<pb_linear_combination<FieldTT>> inputs;
    pb_variable<FieldTT> output;

    std::vector<std::vector<pb_variable<FieldTT>>> after_sbox;
    std::vector<std::vector<pb_variable<FieldTT>>> after_mix;
    std::vector<std::vector<pb_variable<FieldTT>>> sq;
    std::vector<std::vector<pb_variable<FieldTT>>> quad;

    const PoseidonConstants* C;

    poseidon_permutation_gadget(
        protoboard<FieldTT>& pb,
        const std::vector<pb_linear_combination<FieldTT>>& inputs_,
        const pb_variable<FieldTT>& output_,
        const std::string& annotation_prefix = "poseidon")
        : gadget<FieldTT>(pb, annotation_prefix),
          inputs(inputs_), output(output_)
    {
        t = POSEIDON_T;
        RF = POSEIDON_FULL_ROUNDS;
        RP = POSEIDON_PARTIAL_ROUNDS;
        C = &get_poseidon_constants();

        size_t total_rounds = RF + RP;
        size_t half_full = RF / 2;

        after_sbox.resize(total_rounds);
        after_mix.resize(total_rounds);
        sq.resize(total_rounds);
        quad.resize(total_rounds);

        for (size_t r = 0; r < total_rounds; r++) {
            bool full = (r < half_full) || (r >= half_full + RP);
            size_t nsbox = full ? t : 1;
            after_sbox[r].resize(nsbox);
            sq[r].resize(nsbox);
            quad[r].resize(nsbox);
            for (size_t i = 0; i < nsbox; i++) {
                sq[r][i].allocate(pb, FMT(annotation_prefix, "_sq_%zu_%zu", r, i));
                quad[r][i].allocate(pb, FMT(annotation_prefix, "_quad_%zu_%zu", r, i));
                after_sbox[r][i].allocate(pb, FMT(annotation_prefix, "_sbox_%zu_%zu", r, i));
            }
            after_mix[r].resize(t);
            for (size_t i = 0; i < t; i++) {
                after_mix[r][i].allocate(pb, FMT(annotation_prefix, "_mix_%zu_%zu", r, i));
            }
        }
    }

    pb_linear_combination<FieldTT> state_in(size_t r, size_t i) {
        if (r == 0) return inputs[i];
        pb_linear_combination<FieldTT> lc;
        lc.assign(this->pb, pb_variable<FieldTT>(after_mix[r-1][i]));
        return lc;
    }

    void generate_r1cs_constraints() {
        size_t total_rounds = RF + RP;
        size_t half_full = RF / 2;

        for (size_t r = 0; r < total_rounds; r++) {
            bool full = (r < half_full) || (r >= half_full + RP);
            size_t nsbox = full ? t : 1;

            std::vector<pb_linear_combination<FieldTT>> x_ark(t);
            for (size_t i = 0; i < t; i++) {
                pb_linear_combination<FieldTT> lc;
                lc.assign(this->pb, state_in(r, i) + C->ark[r][i]);
                x_ark[i] = lc;
            }

            for (size_t i = 0; i < nsbox; i++) {
                this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldTT>(x_ark[i], x_ark[i], sq[r][i]),
                    FMT(this->annotation_prefix, "_sqc_%zu_%zu", r, i));
                this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldTT>(sq[r][i], sq[r][i], quad[r][i]),
                    FMT(this->annotation_prefix, "_quadc_%zu_%zu", r, i));
                this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldTT>(quad[r][i], x_ark[i], after_sbox[r][i]),
                    FMT(this->annotation_prefix, "_sboxc_%zu_%zu", r, i));
            }

            std::vector<pb_linear_combination<FieldTT>> post(t);
            for (size_t i = 0; i < t; i++) {
                pb_linear_combination<FieldTT> lc;
                if (full) {
                    lc.assign(this->pb, pb_variable<FieldTT>(after_sbox[r][i]));
                } else {
                    if (i == 0) lc.assign(this->pb, pb_variable<FieldTT>(after_sbox[r][0]));
                    else lc = x_ark[i];
                }
                post[i] = lc;
            }

            for (size_t i = 0; i < t; i++) {
                linear_combination<FieldTT> mixlc;
                for (size_t j = 0; j < t; j++) {
                    mixlc = mixlc + C->mds[i][j] * post[j];
                }
                this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldTT>(mixlc, 1, after_mix[r][i]),
                    FMT(this->annotation_prefix, "_mixc_%zu_%zu", r, i));
            }
        }

        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldTT>(
                pb_linear_combination<FieldTT>(pb_variable<FieldTT>(after_mix[total_rounds-1][0])),
                1, output),
            FMT(this->annotation_prefix, "_out"));
    }

    void generate_r1cs_witness() {
        size_t total_rounds = RF + RP;
        size_t half_full = RF / 2;

        std::vector<FieldTT> state(t);
        for (size_t i = 0; i < t; i++) {
            inputs[i].evaluate(this->pb);
            state[i] = this->pb.lc_val(inputs[i]);
        }

        for (size_t r = 0; r < total_rounds; r++) {
            bool full = (r < half_full) || (r >= half_full + RP);
            size_t nsbox = full ? t : 1;

            std::vector<FieldTT> x_ark(t);
            for (size_t i = 0; i < t; i++) x_ark[i] = state[i] + C->ark[r][i];

            std::vector<FieldTT> post(t);
            for (size_t i = 0; i < t; i++) post[i] = x_ark[i];

            for (size_t i = 0; i < nsbox; i++) {
                FieldTT x = x_ark[i];
                FieldTT x2 = x.squared();
                FieldTT x4 = x2.squared();
                FieldTT x5 = x4 * x;
                this->pb.val(sq[r][i]) = x2;
                this->pb.val(quad[r][i]) = x4;
                this->pb.val(after_sbox[r][i]) = x5;
                if (full) post[i] = x5;
                else if (i == 0) post[0] = x5;
            }

            std::vector<FieldTT> mixed(t, FieldTT::zero());
            for (size_t i = 0; i < t; i++) {
                FieldTT acc = FieldTT::zero();
                for (size_t j = 0; j < t; j++) acc = acc + C->mds[i][j] * post[j];
                mixed[i] = acc;
                this->pb.val(after_mix[r][i]) = acc;
            }
            state = mixed;
        }

        this->pb.val(output) = state[0];
    }
};

// 2-to-1 hash gadget: output = Poseidon(left, right).
template<typename FieldTT>
class poseidon_hash2_gadget : public gadget<FieldTT> {
public:
    std::shared_ptr<poseidon_permutation_gadget<FieldTT>> perm;
    pb_variable<FieldTT> output;

    poseidon_hash2_gadget(
        protoboard<FieldTT>& pb,
        const pb_linear_combination<FieldTT>& left,
        const pb_linear_combination<FieldTT>& right,
        const pb_variable<FieldTT>& out,
        const std::string& annotation_prefix = "poseidon_hash2")
        : gadget<FieldTT>(pb, annotation_prefix), output(out)
    {
        std::vector<pb_linear_combination<FieldTT>> in(POSEIDON_T);
        pb_linear_combination<FieldTT> zero;
        zero.assign(pb, 0);
        in[0] = zero;
        in[1] = left;
        in[2] = right;
        perm.reset(new poseidon_permutation_gadget<FieldTT>(pb, in, out, annotation_prefix));
    }

    void generate_r1cs_constraints() { perm->generate_r1cs_constraints(); }
    void generate_r1cs_witness() { perm->generate_r1cs_witness(); }
};

// 1-to-1 hash gadget: output = Poseidon(x).
template<typename FieldTT>
class poseidon_hash1_gadget : public gadget<FieldTT> {
public:
    std::shared_ptr<poseidon_permutation_gadget<FieldTT>> perm;
    pb_variable<FieldTT> output;

    poseidon_hash1_gadget(
        protoboard<FieldTT>& pb,
        const pb_linear_combination<FieldTT>& x,
        const pb_variable<FieldTT>& out,
        const std::string& annotation_prefix = "poseidon_hash1")
        : gadget<FieldTT>(pb, annotation_prefix), output(out)
    {
        std::vector<pb_linear_combination<FieldTT>> in(POSEIDON_T);
        pb_linear_combination<FieldTT> zero;
        zero.assign(pb, 0);
        in[0] = zero;
        in[1] = x;
        in[2] = zero;
        perm.reset(new poseidon_permutation_gadget<FieldTT>(pb, in, out, annotation_prefix));
    }

    void generate_r1cs_constraints() { perm->generate_r1cs_constraints(); }
    void generate_r1cs_witness() { perm->generate_r1cs_witness(); }
};

} // namespace poseidon
#endif // POSEIDON_GADGET_TCC_
