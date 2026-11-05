package main

// This generator creates invented fixtures using a public, deterministic test
// seed. It is an example authoring program, not a key generation utility.
import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/r4venrudy/rudy-logproof/audit"
	"github.com/r4venrudy/rudy-logproof/merkle"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: go run ./examples/demo DIRECTORY")
	}
	folder := os.Args[1]
	if err := os.MkdirAll(folder, 0755); err != nil {
		panic(err)
	}
	seed := sha256.Sum256([]byte("RUDY LOGPROOF PUBLIC SYNTHETIC FIXTURE SEED"))
	private := ed25519.NewKeyFromSeed(seed[:])
	origin := "example.invalid/rudy-release-log"
	leaves := audit.Leaves{Schema: 1, Leaves: []string{}}
	hashes := []merkle.Hash{}
	for i := 0; i < 33; i++ {
		data := []byte(fmt.Sprintf("invented-release-evidence-%02d", i))
		leaves.Leaves = append(leaves.Leaves, base64.StdEncoding.EncodeToString(data))
		hashes = append(hashes, merkle.Leaf(data))
	}
	text := func(nodes []merkle.Hash) []string {
		values := make([]string, len(nodes))
		for i, hash := range nodes {
			values[i] = audit.HashText(hash)
		}
		return values
	}
	bundle := audit.Bundle{Schema: 1, Checkpoints: []audit.Checkpoint{}, Consistency: [][]string{}, Inclusions: []audit.Inclusion{}}
	sizes := []int{0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33}
	for i, size := range sizes {
		checkpoint := audit.Checkpoint{Origin: origin, Size: strconv.Itoa(size),
			Root: audit.HashText(merkle.Root(hashes[:size])), Issued: strconv.Itoa(1000 + i)}
		checkpoint.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, audit.Message(checkpoint)))
		bundle.Checkpoints = append(bundle.Checkpoints, checkpoint)
		if i > 0 {
			path, err := merkle.Consistency(hashes[:size], uint64(sizes[i-1]))
			if err != nil {
				panic(err)
			}
			bundle.Consistency = append(bundle.Consistency, text(path))
		}
		for index := 0; index < size; index++ {
			path, err := merkle.Inclusion(hashes[:size], uint64(index))
			if err != nil {
				panic(err)
			}
			bundle.Inclusions = append(bundle.Inclusions, audit.Inclusion{Checkpoint: i,
				Index: strconv.Itoa(index), Leaf: leaves.Leaves[index], Proof: text(path)})
		}
	}
	write := func(name string, value any) {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(filepath.Join(folder, name), append(data, '\n'), 0644); err != nil {
			panic(err)
		}
	}
	write("trust.json", audit.Key{Schema: 1, Origin: origin, PublicKey: hex.EncodeToString(private.Public().(ed25519.PublicKey))})
	write("anchor.json", bundle.Checkpoints[0])
	write("bundle.json", bundle)
	write("leaves.json", leaves)
}
