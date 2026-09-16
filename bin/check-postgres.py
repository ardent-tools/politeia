#!/usr/bin/env python3
"""Exercise prebuilt durable acceptance binaries against PostgreSQL.

Cargo compilation is declared by the CI stage that produced the two JSON
transcripts below. This harness validates those compiler-artifact records and
then invokes only their exact test executables. CI supplies a PostgreSQL URL;
local source-only installations may instead use Podman or Docker.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
STORAGE_ARTIFACTS_ENV = "POLITEIA_STORAGE_ARTIFACTS_JSON"
PACKAGE_ARTIFACTS_ENV = "POLITEIA_PACKAGE_ARTIFACTS_JSON"


@dataclass(frozen=True)
class ExpectedArtifact:
    """One required executable emitted by Cargo's declared preparation step."""

    label: str
    transcript: str
    manifest: str
    target: str
    kind: tuple[str, ...]
    profile_test: bool


EXPECTED_ARTIFACTS = (
    ExpectedArtifact(
        "storage library tests",
        STORAGE_ARTIFACTS_ENV,
        "crates/politeia-storage/Cargo.toml",
        "politeia_storage",
        ("lib",),
        True,
    ),
    ExpectedArtifact(
        "runtime ledger tests",
        STORAGE_ARTIFACTS_ENV,
        "crates/politeia-storage/Cargo.toml",
        "runtime_ledger",
        ("test",),
        True,
    ),
    ExpectedArtifact(
        "administrative CLI",
        PACKAGE_ARTIFACTS_ENV,
        "crates/politeiad/Cargo.toml",
        "politeia",
        ("bin",),
        False,
    ),
    ExpectedArtifact(
        "daemon CLI",
        PACKAGE_ARTIFACTS_ENV,
        "crates/politeiad/Cargo.toml",
        "politeiad",
        ("bin",),
        False,
    ),
    ExpectedArtifact(
        "commissioning package tests",
        PACKAGE_ARTIFACTS_ENV,
        "crates/politeiad/Cargo.toml",
        "commissioning_package",
        ("test",),
        True,
    ),
)


def repository_path(configured: str) -> Path:
    """Resolve a configured build transcript relative to the repository root."""

    path = Path(configured)
    return path if path.is_absolute() else REPOSITORY_ROOT / path


def default_transcript(environment: str, filename: str) -> Path:
    """Return the declared transcript location, with a public local default."""

    configured = os.environ.get(environment)
    if configured:
        return repository_path(configured)
    return REPOSITORY_ROOT / ".kanon-artifacts" / filename


def read_build_transcript(path: Path, label: str) -> list[dict[str, object]]:
    """Read one complete Cargo JSON stream, refusing partial compiler evidence."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise RuntimeError(f"{label} build transcript is unavailable at {path}: {error}") from error
    if not lines:
        raise RuntimeError(f"{label} build transcript is empty")
    records: list[dict[str, object]] = []
    for number, line in enumerate(lines, start=1):
        if not line:
            raise RuntimeError(f"{label} build transcript has an empty record at line {number}")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"{label} build transcript is truncated or invalid JSON at line {number}: {error}"
            ) from error
        if not isinstance(record, dict):
            raise RuntimeError(f"{label} build transcript record {number} is not an object")
        records.append(record)
    finished = [record for record in records if record.get("reason") == "build-finished"]
    if len(finished) != 1:
        raise RuntimeError(f"{label} build transcript must contain exactly one build-finished record")
    if records[-1] is not finished[0]:
        raise RuntimeError(f"{label} build transcript has records after build-finished")
    if finished[0].get("success") is not True:
        raise RuntimeError(f"{label} build transcript reports an unsuccessful build")
    return records


def artifact_identity(
    record: dict[str, object], label: str
) -> tuple[Path, str, tuple[str, ...], bool]:
    """Return the exact Cargo target identity of one executable artifact record."""

    manifest = record.get("manifest_path")
    target = record.get("target")
    profile = record.get("profile")
    if not isinstance(manifest, str) or not Path(manifest).is_absolute():
        raise RuntimeError(f"{label} artifact has no absolute manifest_path")
    if not isinstance(target, dict):
        raise RuntimeError(f"{label} artifact has no target object")
    if not isinstance(profile, dict) or not isinstance(profile.get("test"), bool):
        raise RuntimeError(f"{label} artifact has no test profile flag")
    name = target.get("name")
    kind = target.get("kind")
    if not isinstance(name, str) or not isinstance(kind, list) or not all(
        isinstance(item, str) for item in kind
    ):
        raise RuntimeError(f"{label} artifact target is incomplete")
    return Path(manifest).resolve(), name, tuple(kind), profile["test"]


def expected_identity(
    artifact: ExpectedArtifact,
) -> tuple[Path, str, tuple[str, ...], bool]:
    """Derive the expected Cargo identity from the one acceptance population."""

    return (
        (REPOSITORY_ROOT / artifact.manifest).resolve(),
        artifact.target,
        artifact.kind,
        artifact.profile_test,
    )


def validate_executable(path: Path, label: str) -> None:
    """Require the exact compiler-emitted executable to remain runnable."""

    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"{label} compiler artifact is not an executable file: {path}")


def prepare_test_binaries(storage_transcript: Path, package_transcript: Path) -> dict[str, Path]:
    """Validate the closed Cargo artifact population before PostgreSQL is touched."""

    transcripts = {
        STORAGE_ARTIFACTS_ENV: read_build_transcript(storage_transcript, "storage"),
        PACKAGE_ARTIFACTS_ENV: read_build_transcript(package_transcript, "package"),
    }
    expected = {expected_identity(artifact): artifact for artifact in EXPECTED_ARTIFACTS}
    expected_manifests = {identity[0] for identity in expected}
    found: dict[tuple[Path, str, tuple[str, ...], bool], Path] = {}
    for transcript, records in transcripts.items():
        for record in records:
            if record.get("reason") != "compiler-artifact":
                continue
            executable = record.get("executable")
            if executable is None:
                continue
            if not isinstance(executable, str) or not Path(executable).is_absolute():
                raise RuntimeError("compiler artifact has no absolute executable path")
            identity = artifact_identity(record, "compiler")
            artifact = expected.get(identity)
            if artifact is None:
                if identity[0] in expected_manifests:
                    raise RuntimeError(
                        "unexpected acceptance executable artifact "
                        f"{identity[1]} with target kind {list(identity[2])} "
                        f"and profile.test={identity[3]}"
                    )
                continue
            if artifact.transcript != transcript:
                raise RuntimeError(f"{artifact.label} appeared in the wrong build transcript")
            if identity in found:
                raise RuntimeError(f"{artifact.label} compiler artifact appears more than once")
            executable_path = Path(executable)
            validate_executable(executable_path, artifact.label)
            found[identity] = executable_path
    missing = [artifact.label for identity, artifact in expected.items() if identity not in found]
    if missing:
        raise RuntimeError(
            "required compiler artifacts are missing: " + ", ".join(sorted(missing))
        )
    return {artifact.label: found[expected_identity(artifact)] for artifact in EXPECTED_ARTIFACTS}


def prepared_binaries() -> dict[str, Path]:
    """Load the two stage-owned transcripts that define this run's binaries."""

    return prepare_test_binaries(
        default_transcript(STORAGE_ARTIFACTS_ENV, "postgres-storage-build.json"),
        default_transcript(PACKAGE_ARTIFACTS_ENV, "postgres-package-build.json"),
    )


def run_tests(database_url: str, binaries: dict[str, Path]) -> int:
    """Run only the accepted executable test population against one database."""

    environment = dict(os.environ, POLITEIA_STORAGE_TEST_DATABASE_URL=database_url)
    if "POLITEIA_ACCEPTANCE_ARTIFACT_FILE" not in environment:
        environment.setdefault(
            "POLITEIA_ACCEPTANCE_ARTIFACT_DIR",
            str(REPOSITORY_ROOT / "target" / "package-acceptance"),
        )
    for artifact in EXPECTED_ARTIFACTS:
        if not artifact.profile_test:
            continue
        result = subprocess.run(
            [str(binaries[artifact.label]), "--ignored", "--test-threads=1"],
            cwd=REPOSITORY_ROOT,
            env=environment,
            check=False,
        )
        if result.returncode:
            return result.returncode
    return 0


def main() -> int:
    try:
        binaries = prepared_binaries()
    except RuntimeError as error:
        print(f"PostgreSQL acceptance preparation refused: {error}", file=sys.stderr)
        return 2
    configured = os.environ.get("POLITEIA_STORAGE_TEST_DATABASE_URL")
    if configured:
        return run_tests(configured, binaries)
    engine = shutil.which("podman") or shutil.which("docker")
    if engine is None:
        print(
            "Set POLITEIA_STORAGE_TEST_DATABASE_URL or install Podman/Docker for a disposable PostgreSQL.",
            file=sys.stderr,
        )
        return 2
    name = f"politeia-acceptance-{uuid.uuid4().hex}"
    password = uuid.uuid4().hex
    subprocess.run(
        [
            engine,
            "run",
            "--detach",
            "--name",
            name,
            "--publish",
            "127.0.0.1::5432",
            "--env",
            "POSTGRES_USER=politeia",
            "--env",
            "POSTGRES_DB=politeia_test",
            "--env",
            f"POSTGRES_PASSWORD={password}",
            "docker.io/library/postgres:16-alpine",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    try:
        port = subprocess.check_output(
            [engine, "port", name, "5432/tcp"], text=True
        ).strip().split(":")[-1]
        deadline = time.monotonic() + 30
        while True:
            ready = subprocess.run(
                [
                    engine,
                    "exec",
                    name,
                    "pg_isready",
                    "-U",
                    "politeia",
                    "-d",
                    "politeia_test",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if ready.returncode == 0:
                break
            if time.monotonic() >= deadline:
                print(
                    "Disposable PostgreSQL did not become ready within 30 seconds.",
                    file=sys.stderr,
                )
                return 2
            time.sleep(0.25)
        return run_tests(
            f"postgresql://politeia:{password}@127.0.0.1:{port}/politeia_test",
            binaries,
        )
    finally:
        subprocess.run([engine, "rm", "--force", name], check=False, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    raise SystemExit(main())
