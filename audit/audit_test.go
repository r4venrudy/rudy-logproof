package audit

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixtures(t *testing.T) (Bundle, Key, Checkpoint) {
	t.Helper()
	var bundle Bundle
	var key Key
	var anchor Checkpoint
	for file, target := range map[string]any{"bundle.json": &bundle, "trust.json": &key, "anchor.json": &anchor} {
		data, err := os.ReadFile("../examples/fixtures/" + file)
		if err != nil {
			t.Fatal(err)
		}
		if err := Decode(data, target); err != nil {
			t.Fatal(err)
		}
	}
	return bundle, key, anchor
}

func TestCheckpointBinding(t *testing.T) {
	bundle, key, anchor := fixtures(t)
	good, err := Verify(bundle, key, anchor, 1020, 10)
	if err != nil || !good.Verified || good.Inclusions != 178 || good.Checkpoints != 14 {
		t.Fatal(good, err)
	}
	cases := []struct {
		name, code string
		change     func(*Bundle, *Key, *Checkpoint)
		now, age   uint64
	}{
		{"pin", "ANCHOR_MISMATCH", func(b *Bundle, k *Key, a *Checkpoint) { b.Checkpoints[0] = b.Checkpoints[1] }, 1020, 10},
		{"origin", "ANCHOR_AUTHENTICATION_FAILED", func(b *Bundle, k *Key, a *Checkpoint) { k.Origin = "another.example" }, 1020, 10},
		{"signature", "CHECKPOINT_AUTHENTICATION_FAILED", func(b *Bundle, k *Key, a *Checkpoint) { b.Checkpoints[1].Issued = "1002" }, 1020, 10},
		{"inclusion", "INCLUSION_PROOF_FAILED", func(b *Bundle, k *Key, a *Checkpoint) { b.Inclusions[0].Leaf = "eA==" }, 1020, 10},
		{"consistency", "CONSISTENCY_PROOF_FAILED", func(b *Bundle, k *Key, a *Checkpoint) { b.Consistency[1] = []string{} }, 1020, 10},
		{"future", "CHECKPOINT_FROM_FUTURE", func(b *Bundle, k *Key, a *Checkpoint) {}, 1010, 100},
		{"stale", "FINAL_CHECKPOINT_STALE", func(b *Bundle, k *Key, a *Checkpoint) {}, 1020, 6},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, k, a := fixtures(t)
			c.change(&b, &k, &a)
			report, err := Verify(b, k, a, c.now, c.age)
			if err != nil || report.Verified || report.Code != c.code {
				t.Fatal(report, err)
			}
		})
	}
}

func TestRFC8032Ed25519Vector(t *testing.T) {
	public, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	signature, _ := hex.DecodeString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	if !ed25519.Verify(public, nil, signature) {
		t.Fatal("RFC 8032 test 1")
	}
	signature[0] ^= 1
	if ed25519.Verify(public, nil, signature) {
		t.Fatal("modified RFC signature")
	}
}

func TestStrictJSON(t *testing.T) {
	for _, input := range []string{
		"null", `{"schema":1,"Schema":1,"leaves":[]}`,
		`{"schema":1,"leaves":[],"leaves":[]}`, `{"schema":1,"leaves":null}`,
		`{"schema":1,"leaves":[]} {}`, `{"schema":1}`, `{"schema":1,"leaves":[],"extra":3}`,
		`{"Schema":1,"leaves":[]}`,
	} {
		var target Leaves
		if err := Decode([]byte(input), &target); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	var target Leaves
	if err := Decode([]byte("{\"schema\":1,\"leaves\":[]}"), &target); err != nil {
		t.Fatal(err)
	}
	for _, number := range []string{"", "00", "-1", "+1", " 1", "18446744073709551616"} {
		if _, err := Number(number); err == nil {
			t.Fatal(number)
		}
	}
	for _, value := range []string{"Zg", "Zh==", "Zg==\n", "===="} {
		if _, err := CanonicalBase64(value, 1024); err == nil {
			t.Fatal(value)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"schema":1,"leaves":[""]}`))
	f.Add([]byte(`{"schema":1,"leaves":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		var leaves Leaves
		if err := Decode(data, &leaves); err == nil {
			LeafHashes(leaves)
			encoded, err := json.Marshal(leaves)
			if err != nil {
				t.Fatal(err)
			}
			var again Leaves
			if err := Decode(encoded, &again); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestJSONPreallocationBudgets(t *testing.T) {
	var target Bundle
	data := []byte(`{"schema":1,"checkpoints":[`)
	for i := 0; i < 257; i++ {
		if i > 0 {
			data = append(data, ',')
		}
		data = append(data, []byte("{}")...)
	}
	data = append(data, []byte(`],"consistency":[],"inclusions":[]}`)...)
	err := Decode(data, &target)
	if err == nil || !strings.Contains(err.Error(), "array count") {
		t.Fatal("checkpoint budget must precede schema allocation", err)
	}
}
