"""Opt-in gate for the controlled live-Batfish integration suite.

Every test in this directory is marked ``integration`` (excluded from
ordinary runs by the ``addopts`` marker expression) AND skipped unless
the operator explicitly opts in with::

    NETOPS_LENS_RUN_BATFISH_INTEGRATION=1

The double gate means a plain ``pytest -q`` never contacts Batfish
through these tests, and even an explicit ``-m integration`` selection
refuses to run without the environment opt-in.
"""

from __future__ import annotations

import os

import pytest

GATE_ENV_VAR = "NETOPS_LENS_RUN_BATFISH_INTEGRATION"


@pytest.fixture(autouse=True)
def require_integration_opt_in():
    """Skip the whole directory unless the operator opted in explicitly."""
    if os.environ.get(GATE_ENV_VAR) != "1":
        pytest.skip(
            f"controlled Batfish integration tests require {GATE_ENV_VAR}=1; "
            "see tests/integration/README.md"
        )
    yield
