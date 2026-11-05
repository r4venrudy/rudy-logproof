package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"testing"
)

func TestProofMatrix(t *testing.T) {
	count := 0
	for size := 0; size <= 80; size++ {
		leaves := make([]Hash, size)
		for i := range leaves {
			leaves[i] = Leaf([]byte{byte(i), byte(size)})
		}
		root := Root(leaves)
		for i := range leaves {
			proof, err := Inclusion(leaves, uint64(i))
			if err != nil || !VerifyInclusion(root, leaves[i], uint64(i), uint64(size), proof) {
				t.Fatalf("inclusion %d/%d", i, size)
			}
			altered := leaves[i]
			altered[0] ^= 1
			if VerifyInclusion(root, altered, uint64(i), uint64(size), proof) {
				t.Fatal("accepted substituted leaf")
			}
			if VerifyInclusion(root, leaves[i], uint64(i), uint64(size), append(proof, Hash{})) {
				t.Fatal("accepted redundant node")
			}
			for j := range proof {
				changed := append([]Hash(nil), proof...)
				changed[j][0] ^= 1
				if VerifyInclusion(root, leaves[i], uint64(i), uint64(size), changed) {
					t.Fatal("accepted changed inclusion")
				}
				count++
			}
			count += 3
		}
		for old := 0; old <= size; old++ {
			proof, err := Consistency(leaves, uint64(old))
			previous := Root(leaves[:old])
			if err != nil || !VerifyConsistency(previous, root, uint64(old), uint64(size), proof) {
				t.Fatalf("consistency %d/%d", old, size)
			}
			if VerifyConsistency(previous, root, uint64(old), uint64(size), append(proof, Hash{})) {
				t.Fatal("accepted redundant consistency node")
			}
			if old > 0 {
				changed := previous
				changed[1] ^= 1
				if VerifyConsistency(changed, root, uint64(old), uint64(size), proof) {
					t.Fatal("accepted changed old root")
				}
			}
			for j := range proof {
				changed := append([]Hash(nil), proof...)
				changed[j][2] ^= 1
				if VerifyConsistency(previous, root, uint64(old), uint64(size), changed) {
					t.Fatal("accepted changed consistency")
				}
				count++
			}
			count += 3
		}
	}
	t.Logf("%d proof conditions over all trees from 0 through 80 leaves", count)
}

func TestKnownHashes(t *testing.T) {
	vectors := []struct {
		data     []byte
		expected string
	}{
		{nil, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"},
		{[]byte(""), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"},
	}
	for _, v := range vectors {
		hash := Leaf(v.data)
		if hex.EncodeToString(hash[:]) != v.expected {
			t.Fatal("leaf vector")
		}
	}
	if Empty() != sha256.Sum256(nil) || Leaf(nil) == Empty() {
		t.Fatal("empty tree and leaf domain separation")
	}
}

func TestBoundaryRejections(t *testing.T) {
	for _, size := range []uint64{0, 1, 2, math.MaxUint64, 1 << 63} {
		if VerifyInclusion(Hash{}, Hash{}, size, size, nil) {
			t.Fatal("out of range")
		}
		if size > 0 && VerifyConsistency(Hash{}, Hash{}, size, 0, nil) {
			t.Fatal("rollback")
		}
	}
	if _, err := Inclusion(nil, 0); err == nil {
		t.Fatal("empty inclusion")
	}
	if _, err := Consistency(nil, 1); err == nil {
		t.Fatal("invalid size")
	}
}

func FuzzVerify(f *testing.F) {
	f.Add(uint64(3), uint64(7), []byte{1, 2, 3})
	f.Add(uint64(math.MaxUint64-1), uint64(math.MaxUint64), make([]byte, 64*32))
	f.Fuzz(func(t *testing.T, a, b uint64, data []byte) {
		if len(data) > 2048 {
			return
		}
		proof := make([]Hash, len(data)/32)
		for i := range proof {
			copy(proof[i][:], data[i*32:(i+1)*32])
		}
		VerifyConsistency(Hash{}, Hash{}, a, b, proof)
		VerifyInclusion(Hash{}, Hash{}, a, b, proof)
	})
}

func TestFullWidthValidTrees(t *testing.T) {
	// A virtual tree of identical leaves permits huge positive vectors without
	// allocating the entries. Powers of two are folded iteratively.
	leaf := Leaf([]byte("virtual leaf"))
	powers := make([]Hash, 64)
	powers[0] = leaf
	for i := 1; i < 64; i++ {
		powers[i] = Node(powers[i-1], powers[i-1])
	}
	root := func(size uint64) Hash {
		var accumulator Hash
		have := false
		for level := 0; level < 64; level++ {
			if size&(uint64(1)<<level) == 0 {
				continue
			}
			if !have {
				accumulator = powers[level]
				have = true
			} else {
				accumulator = Node(powers[level], accumulator)
			}
		}
		if !have {
			return Empty()
		}
		return accumulator
	}
	var proof func(uint64, uint64, bool) []Hash
	proof = func(old, size uint64, complete bool) []Hash {
		if old == size {
			if complete {
				return []Hash{}
			}
			return []Hash{root(size)}
		}
		k := split(size)
		if old <= k {
			return append(proof(old, k, complete), root(size-k))
		}
		return append(proof(old-k, size-k, false), root(k))
	}
	for _, size := range []uint64{1 << 63, (1 << 63) + 1, math.MaxUint64} {
		for _, old := range []uint64{1, (1 << 62) - 1, (1 << 63) - 1, 1 << 63, size} {
			if old > size {
				continue
			}
			path := proof(old, size, true)
			if !VerifyConsistency(root(old), root(size), old, size, path) {
				t.Fatalf("valid full width consistency %d/%d len %d", old, size, len(path))
			}
		}
		for _, index := range []uint64{0, size / 2, size - 1} {
			var inclusion func(uint64, uint64) []Hash
			inclusion = func(i, n uint64) []Hash {
				if n == 1 {
					return []Hash{}
				}
				k := split(n)
				if i < k {
					return append(inclusion(i, k), root(n-k))
				}
				return append(inclusion(i-k, n-k), root(k))
			}
			path := inclusion(index, size)
			if !VerifyInclusion(root(size), leaf, index, size, path) {
				t.Fatal("valid full width inclusion")
			}
		}
	}
	if len(proof((1<<63)-1, math.MaxUint64, true)) != 65 {
		t.Fatal("missing 65-node consistency boundary")
	}
}
