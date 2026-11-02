"""Shared pytest fixtures. Phase 0: Batfish-health guard for later suites."""

from __future__ import annotations

import pytest


def _open_session(host: str, network: str):
    """Connect and select the intended Batfish network (raises when down)."""
    from pybatfish.client.session import Session

    session = Session(host=host)
    session.set_network(network)
    return session


@pytest.fixture(scope="session")
def batfish_host() -> str:
    """Batfish host under test (env override, default localhost)."""
    from netops_lens.config import load_settings

    return load_settings().batfish_host


@pytest.fixture(scope="session")
def batfish_session(batfish_host: str):
    """Live Batfish session on the intended network, or skip with a message.

    Skips are reported, never silent: the skip reason names the host.
    No snapshots are created or modified by this fixture.
    """
    from netops_lens.config import load_settings

    network = load_settings().batfish_network
    try:
        return _open_session(batfish_host, network)
    except Exception:
        pytest.skip(
            f"Batfish unreachable at {batfish_host} (network {network}); integration test skipped"
        )
