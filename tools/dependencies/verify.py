import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

SCHEMA_VERSION = 1
HASH_SIZE = 64

class VerificationError(Exception):
    pass

def repository_root(value=None):
    root = Path(value).expanduser() if value else Path(__file__).resolve().parents[2]
    try:
        return root.resolve(strict=True)
    except OSError as error:
        raise VerificationError(f"repository root is unavailable: {root}: {error}") from error

def within(root, relative, label):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise VerificationError(f"{label} must be a non-empty relative path")
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise VerificationError(f"{label} escapes repository root: {relative}") from error
    return candidate

def string_or_null(value, label):
    if value is not None and (not isinstance(value, str) or not value):
        raise VerificationError(f"{label} must be a non-empty string or null")

def load_manifest(path):
    try:
        with path.open(encoding="utf-8") as stream:
            manifest = json.load(stream)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read manifest {path}: {error}") from error
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION:
        raise VerificationError("manifest schema_version must be 1")
    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, list):
        raise VerificationError("manifest dependencies must be an array")
    return manifest

def verify(root, manifest):
    names = set()
    paths = set()
    checked = 0
    for index, dependency in enumerate(manifest["dependencies"]):
        prefix = f"dependencies[{index}]"
        if not isinstance(dependency, dict):
            raise VerificationError(f"{prefix} must be an object")
        name = dependency.get("name")
        if not isinstance(name, str) or not name:
            raise VerificationError(f"{prefix}.name must be a non-empty string")
        if name in names:
            raise VerificationError(f"duplicate dependency name: {name}")
        names.add(name)
        local = within(root, dependency.get("local_path"), f"{prefix}.local_path")
        key = os.path.normcase(str(local))
        if key in paths:
            raise VerificationError(f"duplicate dependency local_path: {dependency['local_path']}")
        paths.add(key)
        if not local.exists() or not local.is_dir():
            raise VerificationError(f"{prefix}.local_path is not an existing directory: {dependency['local_path']}")
        string_or_null(dependency.get("version"), f"{prefix}.version")
        string_or_null(dependency.get("revision"), f"{prefix}.revision")
        license_path = dependency.get("license_path")
        if license_path is not None:
            license_file = within(root, license_path, f"{prefix}.license_path")
            if not license_file.is_file():
                raise VerificationError(f"{prefix}.license_path is missing: {license_path}")
        required = dependency.get("required_files")
        if not isinstance(required, list):
            raise VerificationError(f"{prefix}.required_files must be an array")
        evidence_paths = set()
        for file_index, evidence in enumerate(required):
            file_prefix = f"{prefix}.required_files[{file_index}]"
            if not isinstance(evidence, dict):
                raise VerificationError(f"{file_prefix} must be an object")
            relative = evidence.get("path")
            if relative in evidence_paths:
                raise VerificationError(f"duplicate required file: {prefix}: {relative}")
            evidence_paths.add(relative)
            file_path = within(local, relative, f"{file_prefix}.path")
            kind = evidence.get("type", "file")
            if kind not in ("file", "directory"):
                raise VerificationError(f"{file_prefix}.type must be file or directory")
            if kind == "file" and not file_path.is_file():
                raise VerificationError(f"required file is missing: {dependency['local_path']}/{relative}")
            if kind == "directory" and not file_path.is_dir():
                raise VerificationError(f"required directory is missing: {dependency['local_path']}/{relative}")
            digest = evidence.get("sha256")
            if digest is not None:
                if kind != "file" or not isinstance(digest, str) or len(digest) != HASH_SIZE or any(c not in "0123456789abcdef" for c in digest):
                    raise VerificationError(f"{file_prefix}.sha256 must be lowercase SHA-256 for a file")
                actual = hashlib.sha256(file_path.read_bytes()).hexdigest()
                if actual != digest:
                    raise VerificationError(f"SHA-256 mismatch for {dependency['local_path']}/{relative}: expected {digest}, got {actual}")
            checked += 1
    return checked

def main(argv=None):
    parser = argparse.ArgumentParser(prog="verify.py", description="Verify AiDA local dependency provenance evidence")
    parser.add_argument("--manifest", default=str(Path(__file__).with_name("manifest.json")), help="manifest JSON path")
    parser.add_argument("--root", help="repository root; defaults to detected repository root")
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit result as JSON")
    args = parser.parse_args(argv)
    try:
        root = repository_root(args.root)
        manifest_path = Path(args.manifest).expanduser().resolve(strict=True)
        checked = verify(root, load_manifest(manifest_path))
        result = {"status":"ok","root":str(root),"manifest":str(manifest_path),"checked_files":checked}
        print(json.dumps(result, sort_keys=True) if args.json_output else f"verified {checked} required files")
        return 0
    except VerificationError as error:
        result = {"status":"error","error":str(error)}
        print(json.dumps(result, sort_keys=True) if args.json_output else f"error: {error}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
