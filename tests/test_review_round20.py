"""Unit tests, twentieth review round: the fail2ban regex of the README
captures the real peer, refused proxy names keyed by name and reason, the
user name rule tied to its constants."""

from __future__ import annotations

import base64
import logging
import re

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import auth, usernames
from tests.conftest import make_settings
from tests.test_review_round15 import _proxy_request

# the failregex of the README, <HOST> as fail2ban would capture it
FAILREGEX = re.compile(r'basic authentication failed for user ".*" from (?P<host>\S+)$')


@pytest.mark.parametrize(
    "name", ['x" from 10.6.6.6', 'x\\" from 10.6.6.6', "y" * 70 + '" from 10.6.6.6']
)
def test_the_documented_failregex_captures_the_real_peer(unit_app, caplog, name):
    caplog.set_level(logging.WARNING)
    client = TestClient(unit_app, client=("10.0.0.9", 50000))
    header = "Basic " + base64.b64encode(f"{name}:pw".encode()).decode()
    assert client.get("/_whoami", headers={"Authorization": header}).status_code == 401
    [line] = [r.getMessage() for r in caplog.records if "basic authentication" in r.getMessage()]
    assert FAILREGEX.search(line)["host"] == "10.0.0.9"


def test_refused_proxy_names_cut_alike_keep_their_own_key(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    monkeypatch.setattr(auth.time, "monotonic", lambda: 1000.0)
    warnings = auth.AuthWarnings()
    settings = make_settings(auth="proxy", basic_users="", proxy_header="X-Remote-User")
    # the same first LOGGED_NAME_MAX characters, a different reason
    for name in ("a" * 70 + "​", "a" * 70 + "️"):
        with pytest.raises(HTTPException):
            auth.user_from_proxy(_proxy_request(name.encode(), warnings), settings)
    assert len(caplog.records) == 2
    assert len(warnings.refused_proxy_user._windows) == 2


def test_the_rule_matches_its_constants():
    message = "the refused characters changed: update USER_NAME_RULE (app/usernames.py)"
    assert usernames.REFUSED_CATEGORIES == {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp", "Zs"}, message
    assert len(usernames.INVISIBLE_CODE_POINTS) == 267, message
