#ifndef POSEIDON_SMT_GADGET_TCC_
#define POSEIDON_SMT_GADGET_TCC_

#include "poseidon_gadget.tcc"

// Sparse-Merkle-tree membership gadget using Poseidon (depth 256).
//
// Proves that, under root `root`, the leaf reached by `path_bits` has value
// `leaf` (we use leaf = 1 to prove existence). path_bits is MSB-first:
// path_bits[0] is the topmost branch (just below the root), path_bits[255] is
// the branch directly above the leaf. siblings[h] is the sibling node at the
// step that combines level-h subtree roots into a level-(h+1) node, ordered
// leaf-first (siblings[0] is the leaf's sibling).
//
// At each step: if the branch bit is 0 the current node is the LEFT child,
// else the RIGHT child.
//   parent = Poseidon( bit ? sibling : cur , bit ? cur : sibling )
//
// All hashing matches the native PoseidonSMT (poseidon_smt.hpp).

namespace poseidon {

using namespace libsnark;

template<typename FieldTT>
class poseidon_smt_gadget : public gadget<FieldTT> {
public:
    static const size_t DEPTH = 256;

    pb_variable<FieldTT> leaf;
    pb_variable_array<FieldTT> path_bits;   // length 256, MSB-first
    pb_variable_array<FieldTT> siblings;    // length 256, leaf-first
    pb_variable<FieldTT> root;

    // For each level: the "current" node value going up (cur[0] = leaf,
    // cur[256] = root). cur[h] is computed from cur[h-1] and siblings[h-1].
    std::vector<pb_variable<FieldTT>> cur;
    // left/right operands fed into each hash (selected by the path bit).
    std::vector<pb_variable<FieldTT>> left_in;
    std::vector<pb_variable<FieldTT>> right_in;
    std::vector<std::shared_ptr<poseidon_hash2_gadget<FieldTT>>> hashers;

    poseidon_smt_gadget(
        protoboard<FieldTT>& pb,
        const pb_variable<FieldTT>& leaf_,
        const pb_variable_array<FieldTT>& path_bits_,
        const pb_variable_array<FieldTT>& siblings_,
        const pb_variable<FieldTT>& root_,
        const std::string& annotation_prefix = "poseidon_smt")
        : gadget<FieldTT>(pb, annotation_prefix),
          leaf(leaf_), path_bits(path_bits_), siblings(siblings_), root(root_)
    {
        cur.resize(DEPTH + 1);
        cur[0] = leaf;
        for (size_t h = 1; h <= DEPTH; h++) {
            cur[h].allocate(pb, FMT(annotation_prefix, "_cur_%zu", h));
        }
        left_in.resize(DEPTH);
        right_in.resize(DEPTH);
        hashers.resize(DEPTH);
        for (size_t h = 0; h < DEPTH; h++) {
            left_in[h].allocate(pb, FMT(annotation_prefix, "_left_%zu", h));
            right_in[h].allocate(pb, FMT(annotation_prefix, "_right_%zu", h));
            pb_linear_combination<FieldTT> l, r;
            l.assign(pb, left_in[h]);
            r.assign(pb, right_in[h]);
            hashers[h].reset(new poseidon_hash2_gadget<FieldTT>(
                pb, l, r, cur[h+1], FMT(annotation_prefix, "_h_%zu", h)));
        }
    }

    // path bit used at hash step h (combining level-h subtree). The leaf step
    // (h=0) is the branch directly above the leaf => path_bits[255]; the top
    // step (h=255) => path_bits[0]. So bit_index(h) = DEPTH-1-h.
    static size_t bit_index(size_t h) { return DEPTH - 1 - h; }

    void generate_r1cs_constraints() {
        for (size_t h = 0; h < DEPTH; h++) {
            size_t bi = bit_index(h);
            // bit must be boolean
            generate_boolean_r1cs_constraint<FieldTT>(this->pb, path_bits[bi],
                FMT(this->annotation_prefix, "_bit_%zu", bi));

            // Selection:
            //   left  = bit ? sibling : cur
            //   right = bit ? cur : sibling
            // left = cur + bit*(sibling - cur)
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldTT>(
                    path_bits[bi],
                    siblings[h] - cur[h],
                    left_in[h] - cur[h]),
                FMT(this->annotation_prefix, "_selL_%zu", h));
            // right = sibling + bit*(cur - sibling)
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldTT>(
                    path_bits[bi],
                    cur[h] - siblings[h],
                    right_in[h] - siblings[h]),
                FMT(this->annotation_prefix, "_selR_%zu", h));

            hashers[h]->generate_r1cs_constraints();
        }
        // root == cur[DEPTH]
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldTT>(
                pb_linear_combination<FieldTT>(cur[DEPTH]), 1, root),
            FMT(this->annotation_prefix, "_rooteq"));
    }

    void generate_r1cs_witness() {
        // leaf already set by caller; cur[0] = leaf value.
        for (size_t h = 0; h < DEPTH; h++) {
            size_t bi = bit_index(h);
            FieldTT bit = this->pb.val(path_bits[bi]);
            FieldTT c = this->pb.val(cur[h]);
            FieldTT s = this->pb.val(siblings[h]);
            FieldTT l, r;
            if (bit == FieldTT::one()) { l = s; r = c; }
            else { l = c; r = s; }
            this->pb.val(left_in[h]) = l;
            this->pb.val(right_in[h]) = r;
            hashers[h]->generate_r1cs_witness();
        }
        this->pb.val(root) = this->pb.val(cur[DEPTH]);
    }
};

} // namespace poseidon

#endif // POSEIDON_SMT_GADGET_TCC_
