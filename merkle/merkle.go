package merkle

import (
	"crypto/sha256"
	"errors"
	"math/bits"
)

type Hash [sha256.Size]byte

func Empty() Hash { return sha256.Sum256(nil) }

func Leaf(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(data)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

func Node(left, right Hash) Hash {
	var data [65]byte
	data[0] = 1
	copy(data[1:33], left[:])
	copy(data[33:], right[:])
	return sha256.Sum256(data[:])
}

func split(n uint64) uint64 { return uint64(1) << (bits.Len64(n-1) - 1) }

func Root(leaves []Hash) Hash {
	if len(leaves) == 0 {
		return Empty()
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := int(split(uint64(len(leaves))))
	return Node(Root(leaves[:k]), Root(leaves[k:]))
}

func Inclusion(leaves []Hash, index uint64) ([]Hash, error) {
	if index >= uint64(len(leaves)) {
		return nil, errors.New("leaf index is outside the tree")
	}
	if len(leaves) == 1 {
		return []Hash{}, nil
	}
	k := split(uint64(len(leaves)))
	if index < k {
		path, err := Inclusion(leaves[:k], index)
		return append(path, Root(leaves[k:])), err
	}
	path, err := Inclusion(leaves[k:], index-k)
	return append(path, Root(leaves[:k])), err
}

func Consistency(leaves []Hash, oldSize uint64) ([]Hash, error) {
	if oldSize > uint64(len(leaves)) {
		return nil, errors.New("previous size exceeds tree size")
	}
	if oldSize == 0 {
		return []Hash{}, nil
	}
	return subproof(leaves, oldSize, true), nil
}

func subproof(leaves []Hash, oldSize uint64, complete bool) []Hash {
	if oldSize == uint64(len(leaves)) {
		if complete {
			return []Hash{}
		}
		return []Hash{Root(leaves)}
	}
	k := split(uint64(len(leaves)))
	if oldSize <= k {
		return append(subproof(leaves[:k], oldSize, complete), Root(leaves[k:]))
	}
	return append(subproof(leaves[k:], oldSize-k, false), Root(leaves[:k]))
}

// Proof nodes are consumed from the leaf toward the root. A recursive
// decomposition avoids n+1 arithmetic for trees near the uint64 boundary.
func VerifyInclusion(root, leaf Hash, index, size uint64, proof []Hash) bool {
	if size == 0 || index >= size || len(proof) > 64 {
		return false
	}
	used := 0
	var fold func(uint64, uint64) (Hash, bool)
	fold = func(i, n uint64) (Hash, bool) {
		if n == 1 {
			return leaf, true
		}
		k := split(n)
		var child Hash
		var ok bool
		if i < k {
			child, ok = fold(i, k)
		} else {
			child, ok = fold(i-k, n-k)
		}
		if !ok || used == len(proof) {
			return Hash{}, false
		}
		sibling := proof[used]
		used++
		if i < k {
			return Node(child, sibling), true
		}
		return Node(sibling, child), true
	}
	got, ok := fold(index, size)
	return ok && used == len(proof) && got == root
}

func VerifyConsistency(oldRoot, newRoot Hash, oldSize, newSize uint64, proof []Hash) bool {
	if oldSize > newSize || len(proof) > 65 {
		return false
	}
	if oldSize == 0 {
		return oldRoot == Empty() && len(proof) == 0 && (newSize != 0 || newRoot == Empty())
	}
	used := 0
	var fold func(uint64, uint64, bool) (Hash, Hash, bool)
	fold = func(m, n uint64, complete bool) (Hash, Hash, bool) {
		if m == n {
			if complete {
				return oldRoot, oldRoot, true
			}
			if used == len(proof) {
				return Hash{}, Hash{}, false
			}
			h := proof[used]
			used++
			return h, h, true
		}
		k := split(n)
		if m <= k {
			a, b, ok := fold(m, k, complete)
			if !ok || used == len(proof) {
				return Hash{}, Hash{}, false
			}
			sibling := proof[used]
			used++
			return a, Node(b, sibling), true
		}
		a, b, ok := fold(m-k, n-k, false)
		if !ok || used == len(proof) {
			return Hash{}, Hash{}, false
		}
		sibling := proof[used]
		used++
		return Node(sibling, a), Node(sibling, b), true
	}
	before, after, ok := fold(oldSize, newSize, true)
	return ok && used == len(proof) && before == oldRoot && after == newRoot
}
