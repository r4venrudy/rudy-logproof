package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/r4venrudy/rudy-logproof/audit"
	"github.com/r4venrudy/rudy-logproof/merkle"
)

const version = "0.1.0-preview"
const usage = `logproof root LEAVES.json
logproof prove --index N LEAVES.json
logproof consistency --old-size N LEAVES.json
logproof verify --key TRUST.json --anchor ANCHOR.json --at SECONDS --max-age SECONDS BUNDLE.json
logproof --version
Use -- before a filename beginning with a dash. Options precede the file.`

func run(args []string, out, diagnostic io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "--version") {
		text := usage
		if args[0] == "--version" {
			text = "logproof " + version
		}
		if _, err := fmt.Fprintln(out, text); err != nil {
			return 2
		}
		return 0
	}
	result, status, err := execute(args)
	if err != nil {
		fmt.Fprintln(diagnostic, "logproof:", err)
		return 2
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		fmt.Fprintln(diagnostic, "logproof: cannot write report")
		return 2
	}
	return status
}

func options(args []string, names []string) (map[string]string, string, error) {
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	values := map[string]string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i != len(args)-2 {
				return nil, "", errors.New(usage)
			}
			return values, args[i+1], nil
		}
		if !strings.HasPrefix(arg, "-") {
			if i != len(args)-1 {
				return nil, "", errors.New(usage)
			}
			return values, arg, nil
		}
		if !allowed[arg] || i+1 >= len(args) {
			return nil, "", errors.New(usage)
		}
		if _, duplicate := values[arg]; duplicate {
			return nil, "", errors.New("duplicate option")
		}
		i++
		values[arg] = args[i]
	}
	return nil, "", errors.New(usage)
}

func execute(args []string) (any, int, error) {
	if len(args) == 0 {
		return nil, 2, errors.New(usage)
	}
	if args[0] == "verify" {
		values, file, err := options(args[1:], []string{"--key", "--anchor", "--at", "--max-age"})
		if err != nil {
			return nil, 2, err
		}
		if len(values) != 4 {
			return nil, 2, errors.New("verify requires key, anchor, at and max-age")
		}
		now, err := audit.Number(values["--at"])
		if err != nil {
			return nil, 2, err
		}
		maxAge, err := audit.Number(values["--max-age"])
		if err != nil {
			return nil, 2, err
		}
		var bundle audit.Bundle
		var key audit.Key
		var anchor audit.Checkpoint
		for _, input := range []struct {
			path   string
			target any
		}{
			{file, &bundle}, {values["--key"], &key}, {values["--anchor"], &anchor},
		} {
			if err := audit.Read(input.path, input.target); err != nil {
				return nil, 2, err
			}
		}
		report, err := audit.Verify(bundle, key, anchor, now, maxAge)
		if err != nil {
			return nil, 2, err
		}
		if !report.Verified {
			return report, 1, nil
		}
		return report, 0, nil
	}
	names := []string{}
	switch args[0] {
	case "root":
	case "prove":
		names = []string{"--index"}
	case "consistency":
		names = []string{"--old-size"}
	default:
		return nil, 2, errors.New(usage)
	}
	values, file, err := options(args[1:], names)
	if err != nil {
		return nil, 2, err
	}
	if len(values) != len(names) {
		return nil, 2, errors.New("missing proof index or previous size")
	}
	var input audit.Leaves
	if err := audit.Read(file, &input); err != nil {
		return nil, 2, err
	}
	leaves, err := audit.LeafHashes(input)
	if err != nil {
		return nil, 2, err
	}
	root := audit.HashText(merkle.Root(leaves))
	size := strconv.Itoa(len(leaves))
	if args[0] == "root" {
		return struct {
			Schema int    `json:"schema"`
			Size   string `json:"size"`
			Root   string `json:"root"`
		}{1, size, root}, 0, nil
	}
	n, err := audit.Number(values[names[0]])
	if err != nil {
		return nil, 2, err
	}
	var path []merkle.Hash
	if args[0] == "prove" {
		path, err = merkle.Inclusion(leaves, n)
	} else {
		path, err = merkle.Consistency(leaves, n)
	}
	if err != nil {
		return nil, 2, err
	}
	nodes := make([]string, len(path))
	for i, hash := range path {
		nodes[i] = audit.HashText(hash)
	}
	if args[0] == "prove" {
		return struct {
			Schema int      `json:"schema"`
			Size   string   `json:"size"`
			Root   string   `json:"root"`
			Index  string   `json:"index"`
			Proof  []string `json:"proof"`
		}{1, size, root, strconv.FormatUint(n, 10), nodes}, 0, nil
	}
	return struct {
		Schema  int      `json:"schema"`
		Size    string   `json:"size"`
		Root    string   `json:"root"`
		OldSize string   `json:"oldSize"`
		OldRoot string   `json:"oldRoot"`
		Proof   []string `json:"proof"`
	}{1, size, root, strconv.FormatUint(n, 10), audit.HashText(merkle.Root(leaves[:int(n)])), nodes}, 0, nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
