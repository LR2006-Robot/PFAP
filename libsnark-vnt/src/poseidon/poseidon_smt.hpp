#ifndef POSEIDON_SMT_HPP_
#define POSEIDON_SMT_HPP_

#include <map>
#include <vector>
#include <string>
#include "poseidon.hpp"
#include "uint256.h"

// Global, public, depth-256 sparse Merkle tree (the "state Merkle Tree").
//
//  * Depth = 256. Leaves are indexed by a 256-bit key.
//  * A leaf's value is 0 (never inserted) or 1 (inserted). A leaf is updated at
//    most once, from 0 to 1.
//  * The key of cmt is path = Poseidon(cmt), taken as the canonical 256-bit
//    big-endian bit string of the field element. path_bit[i] (i = 0 is the MSB)
//    selects the branch at tree level i (level 0 just below the root); the leaf
//    sits at level 256.
//  * Node hashing uses Poseidon 2-to-1: parent = Poseidon(left, right).
//  * Empty subtree roots are precomputed (empty_root[d]) so that proofs and the
//    root can be produced without materializing 2^256 nodes.
//
// Because only ~ (#total ZK txs) leaves are ever set, storage is sparse: we
// keep a map of "occupied" internal node values keyed by (level, index-as-hex).

namespace poseidon {

static const size_t SMT_DEPTH = 256;

class PoseidonSMT {
public:
    PoseidonSMT() {
        // empty_root[0] = empty leaf = 0.
        // empty_root[d] = Poseidon(empty_root[d-1], empty_root[d-1]).
        empty_root_.resize(SMT_DEPTH + 1);
        empty_root_[0] = FieldT::zero();
        for (size_t d = 1; d <= SMT_DEPTH; d++) {
            empty_root_[d] = poseidon_hash2(empty_root_[d-1], empty_root_[d-1]);
        }
    }

    // The current root (height SMT_DEPTH).
    FieldT root() const {
        auto it = nodes_.find(node_key(SMT_DEPTH, std::vector<bool>()));
        if (it != nodes_.end()) return it->second;
        return empty_root_[SMT_DEPTH];
    }

    uint256 root_uint256() const {
        return field_to_uint256_be(root());
    }

    // Compute the 256-bit path for a commitment: path = Poseidon(cmt).
    // path_bits[0] is the MSB (top branch), path_bits[255] is the LSB (leaf).
    static std::vector<bool> compute_path_bits(const uint256& cmt) {
        FieldT c = field_from_cmt(cmt);
        FieldT p = poseidon_hash1(c);
        return field_to_path_bits(p);
    }

    static FieldT compute_path_field(const uint256& cmt) {
        FieldT c = field_from_cmt(cmt);
        return poseidon_hash1(c);
    }

    // Insert a commitment: set its leaf to 1 and update ancestors to the root.
    void insert(const uint256& cmt) {
        std::vector<bool> bits = compute_path_bits(cmt);
        // Walk from leaf (level 0 of node height) up to the root.
        // We store node values along the path; siblings stay empty/occupied as-is.
        // current value at the leaf:
        FieldT cur = FieldT::one();
        // path of branch decisions from root to leaf is bits[0..255].
        // The leaf is at height 0; its parent at height 1, ... root at height 256.
        // index-prefix for a node at height h is bits[0 .. 256-h-1].
        // Set leaf node value.
        set_node(0, prefix(bits, SMT_DEPTH), cur);

        for (size_t h = 1; h <= SMT_DEPTH; h++) {
            // The node at height h covering our leaf has prefix bits[0..256-h-1].
            std::vector<bool> pfx = prefix(bits, SMT_DEPTH - h);
            // Its two children at height h-1: left prefix = pfx + 0, right = pfx + 1.
            std::vector<bool> lpfx = pfx; lpfx.push_back(false);
            std::vector<bool> rpfx = pfx; rpfx.push_back(true);
            FieldT lval = get_node(h-1, lpfx);
            FieldT rval = get_node(h-1, rpfx);
            FieldT parent = poseidon_hash2(lval, rval);
            set_node(h, pfx, parent);
        }
    }

    // Membership proof for a commitment that has been inserted.
    // Returns siblings[0..255] (sibling at each level, from leaf upward:
    // siblings[0] is the sibling of the leaf, siblings[255] is the sibling just
    // below the root) and path_bits (MSB-first as in compute_path_bits).
    struct Proof {
        std::vector<bool> path_bits;        // length 256, MSB-first
        std::vector<uint256> siblings;      // length 256, leaf-first
        uint256 root;
        uint256 path;                       // Poseidon(cmt) as uint256
        bool found;
    };

    Proof prove(const uint256& cmt) const {
        Proof pr;
        std::vector<bool> bits = compute_path_bits(cmt);
        pr.path_bits = bits;
        pr.path = uint256_from_field(compute_path_field(cmt));
        pr.found = (get_node(0, prefix(bits, SMT_DEPTH)) == FieldT::one());

        pr.siblings.resize(SMT_DEPTH);
        for (size_t h = 1; h <= SMT_DEPTH; h++) {
            std::vector<bool> pfx = prefix(bits, SMT_DEPTH - h);
            bool bit = bits[SMT_DEPTH - h]; // branch taken at this level (0=left child)
            std::vector<bool> sibpfx = pfx;
            sibpfx.push_back(!bit);
            FieldT sib = get_node(h-1, sibpfx);
            pr.siblings[h-1] = uint256_from_field(sib);
        }
        pr.root = root_uint256();
        return pr;
    }

    // Convert a field element to its canonical 256-bit big-endian bit vector.
    static std::vector<bool> field_to_path_bits(const FieldT& f) {
        libff::bigint<libff::alt_bn128_r_limbs> b = f.as_bigint();
        std::vector<bool> bits(256, false);
        // b has 4 limbs little-endian; build big-endian bit string (bit 0 = MSB).
        for (size_t i = 0; i < 256; i++) {
            size_t bitpos = 255 - i;           // little-endian bit position
            size_t limb = bitpos / 64;
            size_t off = bitpos % 64;
            bool v = false;
            if (limb < 4) v = ((b.data[limb] >> off) & 1ULL) != 0;
            bits[i] = v;
        }
        return bits;
    }

private:
    std::vector<FieldT> empty_root_;
    // key: "height:hexprefix"
    std::map<std::string, FieldT> nodes_;

    static std::vector<bool> prefix(const std::vector<bool>& bits, size_t len) {
        return std::vector<bool>(bits.begin(), bits.begin() + len);
    }

    static std::string node_key(size_t height, const std::vector<bool>& pfx) {
        std::string s = std::to_string(height);
        s.push_back(':');
        for (bool b : pfx) s.push_back(b ? '1' : '0');
        return s;
    }

    void set_node(size_t height, const std::vector<bool>& pfx, const FieldT& v) {
        nodes_[node_key(height, pfx)] = v;
    }

    FieldT get_node(size_t height, const std::vector<bool>& pfx) const {
        auto it = nodes_.find(node_key(height, pfx));
        if (it != nodes_.end()) return it->second;
        return empty_root_[height];
    }
};

} // namespace poseidon

#endif // POSEIDON_SMT_HPP_
