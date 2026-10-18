"""Write a provenance manifest for an immutable TraceGate-R source revision."""
import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_ARTIFACTS = (
    "logistic_regression.joblib",
    "random_forest.joblib",
    "feature_names.json",
)
PACKAGE_NAME = re.compile(r"^([A-Za-z0-9_.-]+)")


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _dependencies(root: Path) -> list[dict[str, str | None]]:
    entries = []
    for raw_line in (root / "requirements.txt").read_text(encoding="utf-8").splitlines():
        requirement = raw_line.strip()
        match = PACKAGE_NAME.match(requirement)
        if not match:
            continue
        package = match.group(1)
        try:
            installed = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            installed = None
        entries.append({
            "requirement": requirement,
            "installed_version": installed,
        })
    return entries


def _artifact_manifest(artifact_dir: Path) -> dict:
    hashes = {}
    missing = []
    for name in REQUIRED_ARTIFACTS:
        path = artifact_dir / name
        if not path.is_file():
            missing.append(name)
            continue
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        hashes[name] = digest.hexdigest()
    complete = not missing
    identifier = None
    if complete:
        canonical = json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()
        identifier = hashlib.sha256(canonical).hexdigest()
    return {
        "status": "PRESENT_HASHED" if complete else "UNAVAILABLE_OR_INCOMPLETE",
        "identifier": identifier,
        "files_sha256": hashes,
        "missing_files": missing,
    }


def build_manifest(root: Path = ROOT, artifact_dir: Path | None = None) -> dict:
    root = Path(root).resolve()
    if artifact_dir is None:
        artifact_dir = Path(os.environ.get(
            "TRACEGATE_ARTIFACT_DIR",
            str(Path.home() / "tracegate-live" / "artifacts"),
        ))
    else:
        artifact_dir = Path(artifact_dir)

    revision = _git(root, "rev-parse", "HEAD")
    _git(root, "diff-index", "--quiet", "HEAD", "--")
    schema_path = root / "data" / "model_feature_names.json"
    schema_bytes = schema_path.read_bytes()
    schema_names = json.loads(schema_bytes)
    if (
        not isinstance(schema_names, list)
        or len(schema_names) != 48
        or any(not isinstance(name, str) or not name for name in schema_names)
        or len(set(schema_names)) != 48
    ):
        raise ValueError("Release feature schema must contain 48 unique ordered names")
    schema_hash = hashlib.sha256(schema_bytes).hexdigest()
    return {
        "manifest_version": 1,
        "source_revision": revision,
        "source_branch": _git(root, "branch", "--show-current"),
        "built_at_utc": datetime.now(timezone.utc).isoformat(),
        "tracked_source_tree_clean": True,
        "deployment_status": "NOT_DEPLOYED",
        "deployment_target": None,
        "python_version": platform.python_version(),
        "feature_count": len(schema_names),
        "feature_schema_sha256": schema_hash,
        "model_artifacts": _artifact_manifest(artifact_dir),
        "dependencies": _dependencies(root),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "release-manifest.json",
        help="manifest output path (default: release-manifest.json in the repository root)",
    )
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"Refusing to overwrite existing release manifest: {args.output}")
    manifest = build_manifest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
