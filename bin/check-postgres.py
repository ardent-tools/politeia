#!/usr/bin/env python3
"""Exercise durable admission against a configured or disposable PostgreSQL.

CI supplies POLITEIA_STORAGE_TEST_DATABASE_URL. Local source-only installations
can use Podman or Docker; the temporary database and container are removed even
when a test fails. The suites exercise the storage/dispatcher boundary and
the public CLI/daemon package against the same PostgreSQL version.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid


def run_tests(database_url: str) -> int:
    environment = dict(os.environ, POLITEIA_STORAGE_TEST_DATABASE_URL=database_url)
    environment.setdefault(
        "POLITEIA_ACCEPTANCE_ARTIFACT_DIR",
        str(Path(__file__).resolve().parent.parent / "target" / "package-acceptance"),
    )
    suites = [
        ["-p", "politeia-storage"],
        ["-p", "politeiad", "--test", "commissioning_package"],
    ]
    for suite in suites:
        result = subprocess.run(
            ["cargo", "test", *suite, "--locked", "--", "--ignored", "--test-threads=1"],
            cwd=Path(__file__).resolve().parent.parent,
            env=environment,
            check=False,
        )
        if result.returncode:
            return result.returncode
    return 0


def main() -> int:
    configured = os.environ.get("POLITEIA_STORAGE_TEST_DATABASE_URL")
    if configured:
        return run_tests(configured)
    engine = shutil.which("podman") or shutil.which("docker")
    if engine is None:
        print("Set POLITEIA_STORAGE_TEST_DATABASE_URL or install Podman/Docker for a disposable PostgreSQL.", file=sys.stderr)
        return 2
    name = f"politeia-acceptance-{uuid.uuid4().hex}"
    password = uuid.uuid4().hex
    subprocess.run(
        [engine, "run", "--detach", "--name", name,
         "--publish", "127.0.0.1::5432",
         "--env", "POSTGRES_USER=politeia", "--env", "POSTGRES_DB=politeia_test",
         "--env", f"POSTGRES_PASSWORD={password}", "docker.io/library/postgres:16-alpine"],
        check=True, stdout=subprocess.DEVNULL,
    )
    try:
        port = subprocess.check_output(
            [engine, "port", name, "5432/tcp"], text=True,
        ).strip().split(":")[-1]
        deadline = time.monotonic() + 30
        while True:
            ready = subprocess.run(
                [engine, "exec", name, "pg_isready", "-U", "politeia", "-d", "politeia_test"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            )
            if ready.returncode == 0:
                break
            if time.monotonic() >= deadline:
                print("Disposable PostgreSQL did not become ready within 30 seconds.", file=sys.stderr)
                return 2
            time.sleep(0.25)
        return run_tests(f"postgresql://politeia:{password}@127.0.0.1:{port}/politeia_test")
    finally:
        subprocess.run([engine, "rm", "--force", name], check=False, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    raise SystemExit(main())
