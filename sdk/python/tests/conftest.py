import os
import shutil

import pytest


@pytest.fixture(scope="session")
def warden_bin():
    """Locate the warden binary, or skip conformance tests if it isn't built.

    Looks at $WARDEN_BIN, PATH, then the repo's target/{release,debug} dirs.
    """
    candidate = os.environ.get("WARDEN_BIN") or shutil.which("warden")
    if not candidate:
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        for profile in ("release", "debug"):
            path = os.path.join(repo_root, "target", profile, "warden")
            if os.path.exists(path):
                candidate = path
                break
    if not candidate or not os.path.exists(candidate):
        pytest.skip("warden binary not found (build it: cargo build); set WARDEN_BIN to run")
    return candidate
