"""Package a tested native layout with synthetic proofs and runtime license notices."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import zipfile


def package(stage, target, version, go):
    if version != "0.1.0-preview":
        raise ValueError("version does not match source")
    source = Path(__file__).resolve().parents[1]
    stage = stage.resolve()
    binary = stage / "bin" / ("logproof.exe" if os.name == "nt" else "logproof")
    result = subprocess.check_output([binary, "--version"], text=True).strip()
    if result != "logproof " + version:
        raise ValueError("unexpected installed binary version")
    for name in ("README.md", "LICENSE", "SECURITY.md"):
        shutil.copyfile(source / name, stage / name)
    for name in ("docs", "assets"):
        shutil.copytree(source / name, stage / name)
    shutil.copytree(source / "examples/fixtures", stage / "examples/fixtures")
    goroot = Path(subprocess.check_output([go, "env", "GOROOT"], text=True).strip())
    (stage / "licenses").mkdir()
    for name in ("LICENSE", "PATENTS"):
        shutil.copyfile(goroot / name, stage / "licenses" / ("GO-" + name))

    command = [binary, "verify", "--key", stage / "examples/fixtures/trust.json",
               "--anchor", stage / "examples/fixtures/anchor.json",
               "--at", "1020", "--max-age", "10", stage / "examples/fixtures/bundle.json"]
    proof = json.loads(subprocess.check_output(command, text=True))
    if not proof["verified"] or proof["inclusions"] != 178 or proof["checkpoints"] != 14:
        raise ValueError("installed signed fixture verification failed")

    output = source / "dist"
    output.mkdir(exist_ok=True)
    archive = output / (f"logproof-{version}-{target}" + (".zip" if target == "windows-x64" else ".tar.gz"))
    entries = sorted(stage.rglob("*"))
    if any(path.is_symlink() or not (path.is_file() or path.is_dir()) for path in entries):
        raise ValueError("unexpected package file type")
    files = [path for path in entries if path.is_file()]
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as writer:
            for path in files:
                writer.write(path, path.relative_to(stage).as_posix())
    else:
        with tarfile.open(archive, "x:gz") as writer:
            for path in files:
                writer.add(path, arcname=path.relative_to(stage).as_posix(), recursive=False)
    print("Verified installed signed fixture and packaged", archive.name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", type=Path)
    parser.add_argument("target", choices=("windows-x64", "linux-x64", "macos-arm64"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    package(args.stage, args.target, args.version, args.go)
