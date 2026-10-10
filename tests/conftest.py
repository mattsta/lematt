"""Test-wide safety: no network access, and no state leaking between tests."""

import httpx
import pytest
from loguru import logger


@pytest.fixture(autouse=True)
def isolated_logging():
    """Remove the log handlers a test installed once it ends.

    setup_logging() binds loguru to the current sys.stderr, which under
    capsys is a per-test stream that pytest closes afterwards. A later test
    logging through that handler fails with "I/O operation on closed file".
    """
    yield
    logger.remove()


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Fail any HTTP request that isn't served by an httpx.MockTransport.

    ACME tests run against tests/fake_acme.py; a request escaping to the
    network would hit a real CA (e.g. Let's Encrypt staging).
    """

    def refuse(self, request):
        raise AssertionError(f"test attempted real network access: {request.url}")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", refuse)
