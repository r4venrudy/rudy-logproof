package audit

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/r4venrudy/rudy-logproof/merkle"
)

type Key struct {
	Schema    int    `json:"schema"`
	Origin    string `json:"origin"`
	PublicKey string `json:"publicKey"`
}

type Checkpoint struct {
	Origin    string `json:"origin"`
	Size      string `json:"size"`
	Root      string `json:"root"`
	Issued    string `json:"issued"`
	Signature string `json:"signature"`
}

type Inclusion struct {
	Checkpoint int      `json:"checkpoint"`
	Index      string   `json:"index"`
	Leaf       string   `json:"leaf"`
	Proof      []string `json:"proof"`
}

type Bundle struct {
	Schema      int          `json:"schema"`
	Checkpoints []Checkpoint `json:"checkpoints"`
	Consistency [][]string   `json:"consistency"`
	Inclusions  []Inclusion  `json:"inclusions"`
}

type Report struct {
	Schema      int    `json:"schema"`
	Verified    bool   `json:"verified"`
	Code        string `json:"code"`
	Checkpoints int    `json:"checkpoints"`
	Inclusions  int    `json:"inclusions"`
	FinalSize   string `json:"finalSize"`
	FinalRoot   string `json:"finalRoot"`
}

func Number(value string) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != value {
		return 0, errors.New("expected a canonical uint64 decimal string")
	}
	return n, nil
}

func ParseHash(value string) (merkle.Hash, error) {
	var hash merkle.Hash
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != len(hash) || hex.EncodeToString(raw) != value {
		return hash, errors.New("expected a lowercase SHA-256 hex value")
	}
	copy(hash[:], raw)
	return hash, nil
}

func HashText(hash merkle.Hash) string { return hex.EncodeToString(hash[:]) }

func Origin(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range []byte(value) {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func Message(checkpoint Checkpoint) []byte {
	return []byte("RUDY LOGPROOF CHECKPOINT 1\n" + checkpoint.Origin + "\n" +
		checkpoint.Size + "\n" + checkpoint.Root + "\n" + checkpoint.Issued + "\n")
}

func CanonicalBase64(value string, limit int) ([]byte, error) {
	if len(value) > base64.StdEncoding.EncodedLen(limit) {
		return nil, errors.New("base64 value exceeds the decoded budget")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(data) > limit || base64.StdEncoding.EncodeToString(data) != value {
		return nil, errors.New("expected canonical padded base64")
	}
	return data, nil
}

type parsedCheckpoint struct {
	size, issued uint64
	root         merkle.Hash
	signature    []byte
}

func parseCheckpoint(c Checkpoint) (parsedCheckpoint, error) {
	var p parsedCheckpoint
	var err error
	if !Origin(c.Origin) {
		return p, errors.New("invalid checkpoint origin")
	}
	if p.size, err = Number(c.Size); err != nil {
		return p, err
	}
	if p.issued, err = Number(c.Issued); err != nil {
		return p, err
	}
	if p.root, err = ParseHash(c.Root); err != nil {
		return p, err
	}
	if p.signature, err = CanonicalBase64(c.Signature, ed25519.SignatureSize); err != nil {
		return p, err
	}
	if len(p.signature) != ed25519.SignatureSize {
		return p, errors.New("invalid signature length")
	}
	if p.size == 0 && p.root != merkle.Empty() {
		return p, errors.New("nonempty root for an empty tree")
	}
	return p, nil
}

func hashes(values []string) ([]merkle.Hash, error) {
	if values == nil || len(values) > 65 {
		return nil, errors.New("proof must have zero to 65 nodes")
	}
	result := make([]merkle.Hash, len(values))
	for i, value := range values {
		h, err := ParseHash(value)
		if err != nil {
			return nil, err
		}
		result[i] = h
	}
	return result, nil
}

func Verify(bundle Bundle, key Key, anchor Checkpoint, now, maxAge uint64) (Report, error) {
	report := Report{Schema: 1, FinalSize: "", FinalRoot: ""}
	if key.Schema != 1 || !Origin(key.Origin) {
		return report, errors.New("invalid trust key schema or origin")
	}
	public, err := hex.DecodeString(key.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize || hex.EncodeToString(public) != key.PublicKey {
		return report, errors.New("invalid pinned Ed25519 public key")
	}
	if bundle.Schema != 1 || len(bundle.Checkpoints) == 0 || len(bundle.Checkpoints) > 256 ||
		len(bundle.Consistency) != len(bundle.Checkpoints)-1 ||
		bundle.Inclusions == nil || len(bundle.Inclusions) > 10000 {
		return report, errors.New("invalid bundle schema or count limits")
	}
	anchorParsed, err := parseCheckpoint(anchor)
	if err != nil {
		return report, err
	}
	checkpoints := make([]parsedCheckpoint, len(bundle.Checkpoints))
	paths := make([][]merkle.Hash, len(bundle.Consistency))
	for i, checkpoint := range bundle.Checkpoints {
		p, err := parseCheckpoint(checkpoint)
		if err != nil {
			return report, err
		}
		checkpoints[i] = p
	}
	for i, path := range bundle.Consistency {
		h, err := hashes(path)
		if err != nil {
			return report, err
		}
		paths[i] = h
	}
	proofNodes := make([][]merkle.Hash, len(bundle.Inclusions))
	leaves := make([]merkle.Hash, len(bundle.Inclusions))
	indices := make([]uint64, len(bundle.Inclusions))
	total := 0
	for i, inclusion := range bundle.Inclusions {
		if inclusion.Checkpoint < 0 || inclusion.Checkpoint >= len(checkpoints) {
			return report, errors.New("inclusion references an unknown checkpoint")
		}
		if indices[i], err = Number(inclusion.Index); err != nil {
			return report, err
		}
		data, err := CanonicalBase64(inclusion.Leaf, 1024*1024)
		if err != nil {
			return report, err
		}
		total += len(data)
		if total > 16*1024*1024 {
			return report, errors.New("leaf data exceeds 16 MiB aggregate budget")
		}
		leaves[i] = merkle.Leaf(data)
		if proofNodes[i], err = hashes(inclusion.Proof); err != nil {
			return report, err
		}
	}
	fail := func(code string) (Report, error) { report.Code = code; return report, nil }
	if anchor.Origin != key.Origin || !ed25519.Verify(public, Message(anchor), anchorParsed.signature) {
		return fail("ANCHOR_AUTHENTICATION_FAILED")
	}
	// Pin every field, including the signature, to the caller's saved anchor.
	if bundle.Checkpoints[0] != anchor {
		return fail("ANCHOR_MISMATCH")
	}
	for i, checkpoint := range bundle.Checkpoints {
		current := checkpoints[i]
		if checkpoint.Origin != key.Origin || !ed25519.Verify(public, Message(checkpoint), current.signature) {
			return fail("CHECKPOINT_AUTHENTICATION_FAILED")
		}
		if current.issued > now {
			return fail("CHECKPOINT_FROM_FUTURE")
		}
		if i > 0 {
			previous := checkpoints[i-1]
			if current.issued < previous.issued {
				return fail("CHECKPOINT_TIME_ROLLBACK")
			}
			if !merkle.VerifyConsistency(previous.root, current.root, previous.size, current.size, paths[i-1]) {
				return fail("CONSISTENCY_PROOF_FAILED")
			}
		}
		report.Checkpoints++
	}
	final := checkpoints[len(checkpoints)-1]
	if now-final.issued > maxAge {
		return fail("FINAL_CHECKPOINT_STALE")
	}
	for i, inclusion := range bundle.Inclusions {
		checkpoint := checkpoints[inclusion.Checkpoint]
		if !merkle.VerifyInclusion(checkpoint.root, leaves[i], indices[i], checkpoint.size, proofNodes[i]) {
			return fail("INCLUSION_PROOF_FAILED")
		}
		report.Inclusions++
	}
	report.Verified = true
	report.Code = "VERIFIED"
	report.FinalSize = bundle.Checkpoints[len(checkpoints)-1].Size
	report.FinalRoot = bundle.Checkpoints[len(checkpoints)-1].Root
	return report, nil
}

// Leaves is a bounded generator input. Data bytes are hashed without text normalization.
type Leaves struct {
	Schema int      `json:"schema"`
	Leaves []string `json:"leaves"`
}

func LeafHashes(input Leaves) ([]merkle.Hash, error) {
	if input.Schema != 1 || input.Leaves == nil || len(input.Leaves) > 100000 {
		return nil, errors.New("expected up to 100000 base64 leaves")
	}
	result := make([]merkle.Hash, len(input.Leaves))
	total := 0
	for i, value := range input.Leaves {
		data, err := CanonicalBase64(value, 1024*1024)
		if err != nil {
			return nil, err
		}
		total += len(data)
		if total > 16*1024*1024 {
			return nil, errors.New("leaf data exceeds aggregate budget")
		}
		result[i] = merkle.Leaf(data)
	}
	return result, nil
}
