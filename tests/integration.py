"""Independent tree construction, iterative proof verification, and CLI contracts."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
from tempfile import TemporaryDirectory

binary = Path(sys.argv[1]).resolve()
source = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else Path(__file__).resolve().parents[1]
fixtures = source / "examples/fixtures"
checks = 0


def check(value, context):
    global checks
    checks += 1
    if not value:
        raise AssertionError(context)


def leaf(data):
    return hashlib.sha256(b"\0" + data).digest()


def node(left, right):
    return hashlib.sha256(b"\1" + left + right).digest()


def root(hashes):
    # Pair adjacent nodes and promote an odd last node at each level.
    if not hashes:
        return hashlib.sha256(b"").digest()
    level = hashes[:]
    while len(level) > 1:
        level = [node(level[i], level[i+1]) if i+1 < len(level) else level[i]
                 for i in range(0, len(level), 2)]
    return level[0]


def inclusion(hashes, index):
    path = []
    level = hashes[:]
    while len(level) > 1:
        sibling = index ^ 1
        if sibling < len(level):
            path.append(level[sibling])
        level = [node(level[i], level[i+1]) if i+1 < len(level) else level[i]
                 for i in range(0, len(level), 2)]
        index //= 2
    return path


def consistent(old, new, first, second, path):
    # Iterative two-root verification, independent of the native recursive fold.
    if first > second:
        return False
    if first == 0:
        return not path and old == root([]) and (second != 0 or new == root([]))
    if first == second:
        return not path and old == new
    if not path:
        return False
    values = path[:]
    if first & (first-1) == 0:
        values.insert(0, old)
    left, right = first-1, second-1
    while left & 1:
        left >>= 1
        right >>= 1
    previous = current = values[0]
    for sibling in values[1:]:
        if right == 0:
            return False
        if left & 1 or left == right:
            previous = node(sibling, previous)
            current = node(sibling, current)
            while left and not left & 1:
                left >>= 1
                right >>= 1
        else:
            current = node(current, sibling)
        left >>= 1
        right >>= 1
    return right == 0 and previous == old and current == new


with TemporaryDirectory() as scratch:
    temporary = Path(scratch)

    def run(*args, status=0):
        result = subprocess.run([binary, *map(str, args)], capture_output=True,
                                text=True, encoding="utf-8", timeout=20)
        check(result.returncode == status, (args, result.returncode, result.stderr, result.stdout[:200]))
        if status == 2:
            check(not result.stdout and result.stderr.startswith("logproof:"), result)
            return None
        check(not result.stderr, result.stderr)
        return json.loads(result.stdout)

    def write(value):
        path = temporary / "input.json"
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        return path

    def verify(bundle, *, code="VERIFIED", status=0, now="1020", age="10", trust=None, anchor=None):
        result = run("verify", "--key", trust or fixtures / "trust.json",
                     "--anchor", anchor or fixtures / "anchor.json", "--at", now, "--max-age", age,
                     write(bundle), status=status)
        if result is not None:
            check(result["code"] == code and result["verified"] == (status == 0), result)
        return result

    bundle = json.loads((fixtures / "bundle.json").read_text())
    data = json.loads((fixtures / "leaves.json").read_text())
    hashes = [leaf(base64.b64decode(item)) for item in data["leaves"]]
    accepted = verify(bundle)
    check(accepted["inclusions"] == 178 and accepted["checkpoints"] == 14, accepted)
    for checkpoint in bundle["checkpoints"]:
        size = int(checkpoint["size"])
        check(root(hashes[:size]).hex() == checkpoint["root"], checkpoint)
    for i, path in enumerate(bundle["consistency"]):
        a, b = bundle["checkpoints"][i:i+2]
        proof = [bytes.fromhex(h) for h in path]
        check(consistent(bytes.fromhex(a["root"]), bytes.fromhex(b["root"]),
                         int(a["size"]), int(b["size"]), proof), (a, b))
    for row in bundle["inclusions"]:
        checkpoint = bundle["checkpoints"][row["checkpoint"]]
        size, index = int(checkpoint["size"]), int(row["index"])
        check([h.hex() for h in inclusion(hashes[:size], index)] == row["proof"], row)

    cases = [
        ("CHECKPOINT_AUTHENTICATION_FAILED", lambda b: b["checkpoints"][2].update(issued="1003")),
        ("CONSISTENCY_PROOF_FAILED", lambda b: b["consistency"][2].clear()),
        ("INCLUSION_PROOF_FAILED", lambda b: b["inclusions"][0].update(leaf="eA==")),
        ("INCLUSION_PROOF_FAILED", lambda b: b["inclusions"][0].update(index="1")),
        ("ANCHOR_MISMATCH", lambda b: b["checkpoints"].__setitem__(0, b["checkpoints"][1])),
    ]
    for diagnostic, change in cases:
        altered = copy.deepcopy(bundle)
        change(altered)
        verify(altered, code=diagnostic, status=1)
    verify(bundle, code="FINAL_CHECKPOINT_STALE", status=1, age="6")
    verify(bundle, code="CHECKPOINT_FROM_FUTURE", status=1, now="1010")
    verify(bundle, age="7")  # Equality at the freshness boundary.
    for invalid in [
        b'null', b'{"schema":1,"Schema":1,"leaves":[]}',
        b'{"schema":1,"leaves":[],"leaves":[]}', b'{"schema":1,"leaves":null}',
        b'{"schema":1,"leaves":[]} true', {"schema":1,"leaves":["Zh=="]},
        {"schema":1,"leaves":["Zg==\n"]}, {"schema":1,"leaves":[],"unknown":False},
    ]:
        run("root", write(invalid), status=2)
    altered = copy.deepcopy(bundle)
    altered["checkpoints"][2]["size"] = "02"
    verify(altered, status=2)
    altered = copy.deepcopy(bundle)
    altered["consistency"][0] = None
    verify(altered, status=2)
    run("prove", "--index", "18446744073709551616", fixtures / "leaves.json", status=2)
    run("root", "--unknown", fixtures / "leaves.json", status=2)
    run("verify", "--key", fixtures / "trust.json", write(bundle), status=2)

    rng = random.Random(69629162)
    for trial in range(160):
        size = trial if trial < 34 else rng.randrange(1, 145)
        entries = [rng.randbytes(rng.randrange(0, 97)) for _ in range(size)]
        leaves = [leaf(data) for data in entries]
        document = {"schema":1, "leaves":[base64.b64encode(data).decode() for data in entries]}
        path = write(document)
        report = run("root", path)
        check(report["size"] == str(size) and report["root"] == root(leaves).hex(), report)
        if size:
            for index in sorted({0, size//2, size-1}):
                report = run("prove", "--index", str(index), path)
                check(report["index"] == str(index) and report["size"] == str(size), report)
                check(report["root"] == root(leaves).hex(), report)
                check(report["proof"] == [h.hex() for h in inclusion(leaves, index)], report)
        for old in sorted({0, size//2, size}):
            report = run("consistency", "--old-size", str(old), path)
            proof = [bytes.fromhex(value) for value in report["proof"]]
            check(report["oldSize"] == str(old) and report["size"] == str(size), report)
            check(consistent(root(leaves[:old]), root(leaves), old, size, proof), report)
            if proof:
                changed = proof[:]
                changed[0] = bytes([changed[0][0] ^ 1]) + changed[0][1:]
                check(not consistent(root(leaves[:old]), root(leaves), old, size, changed), report)

    # The -- delimiter supports a filename that would otherwise be an option.
    dash_path = temporary / "-leaves.json"
    dash_path.write_text('{"schema":1,"leaves":[]}')
    run("root", "--", dash_path)
print(f"{checks} independent conditions across 160 generated trees and signed bundle cases")
