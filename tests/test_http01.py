"""http-01 self-check: tolerate a challenge server that is still starting.

Prepare actions (e.g. `ssh host leforward.py ...`) start asynchronously, so
the first self-check can race them and find nothing listening yet.
"""

import httpx
import pytest

from lematt.acme import Http01Solver
from lematt.acme.errors import ChallengeError

KEY_AUTHORIZATION = "token.thumbprint"


def solver_for(tmp_path, handler, sleeps: list[float]) -> Http01Solver:
    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    return Http01Solver(tmp_path, client=client, sleep=sleeps.append)


def test_self_check_waits_for_a_starting_challenge_server(tmp_path):
    attempts = []

    def handler(request):
        attempts.append(request.url)
        if len(attempts) < 3:
            raise httpx.ConnectError("Connection refused", request=request)
        return httpx.Response(200, text=KEY_AUTHORIZATION)

    sleeps: list[float] = []
    solver_for(tmp_path, handler, sleeps).present(
        "mail.example.com", "token", KEY_AUTHORIZATION
    )

    assert len(attempts) == 3
    assert len(sleeps) == 2


def test_self_check_gives_up_when_the_server_never_comes_up(tmp_path):
    def handler(request):
        raise httpx.ConnectError("Connection refused", request=request)

    sleeps: list[float] = []
    solver = solver_for(tmp_path, handler, sleeps)

    with pytest.raises(ChallengeError, match="challenge not reachable"):
        solver.present("mail.example.com", "token", KEY_AUTHORIZATION)

    assert len(sleeps) == len(solver.connect_retry_delays)
    assert sum(sleeps) < 10  # bounded: a dead forwarder fails fast


def test_wrong_content_fails_immediately_without_retrying(tmp_path):
    attempts = []

    def handler(request):
        attempts.append(request.url)
        return httpx.Response(404, text="not found")

    sleeps: list[float] = []

    with pytest.raises(ChallengeError, match="is challengeDropDir served there"):
        solver_for(tmp_path, handler, sleeps).present(
            "example.com", "token", KEY_AUTHORIZATION
        )

    assert len(attempts) == 1
    assert sleeps == []
