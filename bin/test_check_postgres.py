"""Static falsifiers for the PostgreSQL acceptance artifact contract."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("check-postgres.py")
SPEC = importlib.util.spec_from_file_location("check_postgres", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load PostgreSQL acceptance harness")
CHECK_POSTGRES = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK_POSTGRES
SPEC.loader.exec_module(CHECK_POSTGRES)


class CompilerArtifactContractTests(unittest.TestCase):
    """The harness must refuse incomplete or substituted compiler evidence."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.executables = {}
        for index, artifact in enumerate(CHECK_POSTGRES.EXPECTED_ARTIFACTS):
            executable = self.root / f"artifact-{index}"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            self.executables[artifact] = executable

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def artifact_record(self, artifact: object) -> dict[str, object]:
        expected = artifact
        return {
            "reason": "compiler-artifact",
            "manifest_path": str(
                (CHECK_POSTGRES.REPOSITORY_ROOT / expected.manifest).resolve()
            ),
            "target": {"name": expected.target, "kind": list(expected.kind)},
            "profile": {"test": expected.profile_test},
            "executable": str(self.executables[expected]),
        }

    def write_transcript(
        self, name: str, records: list[dict[str, object]], success: bool = True
    ) -> Path:
        path = self.root / name
        lines = [json.dumps(record) for record in records]
        lines.append(json.dumps({"reason": "build-finished", "success": success}))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def complete_transcripts(self) -> tuple[Path, Path]:
        storage = [
            self.artifact_record(artifact)
            for artifact in CHECK_POSTGRES.EXPECTED_ARTIFACTS
            if artifact.transcript == CHECK_POSTGRES.STORAGE_ARTIFACTS_ENV
        ]
        package = [
            self.artifact_record(artifact)
            for artifact in CHECK_POSTGRES.EXPECTED_ARTIFACTS
            if artifact.transcript == CHECK_POSTGRES.PACKAGE_ARTIFACTS_ENV
        ]
        return (
            self.write_transcript("storage.json", storage),
            self.write_transcript("package.json", package),
        )

    def test_accepts_exact_compiler_artifact_population(self) -> None:
        storage, package = self.complete_transcripts()
        binaries = CHECK_POSTGRES.prepare_test_binaries(storage, package)
        self.assertEqual(
            set(binaries),
            {
                "storage library tests",
                "runtime ledger tests",
                "commissioning package tests",
                "administrative CLI",
                "daemon CLI",
            },
        )

    def test_refuses_missing_compiler_artifact(self) -> None:
        storage, package = self.complete_transcripts()
        storage.write_text(
            "\n".join(storage.read_text(encoding="utf-8").splitlines()[1:]) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "required compiler artifacts are missing"):
            CHECK_POSTGRES.prepare_test_binaries(storage, package)

    def test_refuses_duplicate_compiler_artifact(self) -> None:
        storage, package = self.complete_transcripts()
        lines = storage.read_text(encoding="utf-8").splitlines()
        storage.write_text(
            "\n".join([*lines[:-1], lines[0], lines[-1]]) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeError, "appears more than once"):
            CHECK_POSTGRES.prepare_test_binaries(storage, package)

    def test_refuses_wrong_executable_target(self) -> None:
        storage, package = self.complete_transcripts()
        records = [json.loads(line) for line in storage.read_text(encoding="utf-8").splitlines()]
        records[0]["target"]["name"] = "substituted_target"
        storage.write_text(
            "\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeError, "unexpected acceptance executable artifact"):
            CHECK_POSTGRES.prepare_test_binaries(storage, package)

    def test_refuses_wrong_test_harness_profile(self) -> None:
        storage, package = self.complete_transcripts()
        records = [json.loads(line) for line in storage.read_text(encoding="utf-8").splitlines()]
        records[0]["profile"]["test"] = False
        storage.write_text(
            "\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeError, "unexpected acceptance executable artifact"):
            CHECK_POSTGRES.prepare_test_binaries(storage, package)

    def test_refuses_truncated_or_failed_build_metadata(self) -> None:
        storage, package = self.complete_transcripts()
        storage.write_text('{"reason":"compiler-artifact"\n', encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "truncated or invalid JSON"):
            CHECK_POSTGRES.prepare_test_binaries(storage, package)

        storage, package = self.complete_transcripts()
        records = [json.loads(line) for line in storage.read_text(encoding="utf-8").splitlines()]
        records[-1]["success"] = False
        storage.write_text(
            "\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeError, "unsuccessful build"):
            CHECK_POSTGRES.prepare_test_binaries(storage, package)


if __name__ == "__main__":
    unittest.main()
