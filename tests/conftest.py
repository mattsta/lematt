"""Test-wide safety: no test may reach a real network service."""

import httpx
import pytest


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Fail any HTTP request that isn't served by an httpx.MockTransport.

    ACME tests run against tests/fake_acme.py; a request escaping to the
    network would hit a real CA (e.g. Let's Encrypt staging).
    """

    def refuse(self, request):
        raise AssertionError(f"test attempted real network access: {request.url}")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", refuse)
