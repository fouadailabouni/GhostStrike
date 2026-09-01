"""
Adversarial tests for lib/scope_check.py -- the scope boundary checker that
gs_policy_gate relies on to decide whether a module is allowed to run
against a given target.

These deliberately try to break scope enforcement with the input shapes
listed in the project's own architecture notes as known-risky: IPv6, URLs
with embedded userinfo, unicode/punycode domains, and wildcard syntax.

Two kinds of test here:
  - Safety regression guards: prove a suspected bypass does NOT work today.
    These must always pass -- if one starts failing, that's a real
    regression in scope enforcement.
  - xfail: document a real, currently-unfixed gap. These are expected to
    fail today; if one starts passing, pytest reports XPASS loudly, which
    is exactly the signal you want when the underlying gap gets fixed.

(c) 2026 Fouad Ailabouni. All rights reserved.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bash_scripts_for_pentest" / "lib"))
import scope_check  # noqa: E402


# ── Safety regression guards: prove these do NOT bypass scope today ───────

def test_userinfo_does_not_hide_real_host():
    """http://good.com@evil.com/ must resolve to the REAL host (evil.com),
    not the userinfo-looking prefix -- a classic SSRF/scope-check bypass
    shape. urlparse handles this correctly; this test guards against a
    future refactor accidentally regressing it."""
    assert scope_check.extract_host("http://good.com@evil.com/") == "evil.com"
    assert not scope_check.matches("http://good.com@evil.com/", "good.com")


def test_ipv6_bracketed_url_extracts_correctly():
    assert scope_check.extract_host("http://[::1]:8080/") == "::1"


def test_ipv6_cidr_containment_is_real():
    assert scope_check.matches("2001:db8::1", "2001:db8::/32")
    assert not scope_check.matches("2001:db8::1", "2001:db9::/32")


def test_ipv4_and_ipv6_never_cross_match():
    """A v4-shaped target must never match a v6-shaped scope entry or vice
    versa, even where a naive comparison might coincidentally line up."""
    assert not scope_check.matches("127.0.0.1", "::1/128")
    assert not scope_check.matches("::1", "127.0.0.1/32")


def test_subdomain_suffix_match_is_not_substring_containment():
    """example.com must not match evil-example.com.attacker.net just
    because 'example.com' appears as a substring."""
    assert scope_check.matches("api.example.com", "example.com")
    assert not scope_check.matches("evil-example.com.attacker.net", "example.com")


def test_exact_hostname_match():
    assert scope_check.matches("example.com", "example.com")
    assert not scope_check.matches("example.com", "example.org")


# ── xfail: real, documented, currently-unfixed gaps ────────────────────────

@pytest.mark.xfail(reason=(
    "No IDNA/punycode normalization: a scope exclusion written as a plain "
    "unicode domain does not match its punycode-encoded equivalent (or vice "
    "versa), even though they're the same domain. An operator excluding "
    "'münchen.de' would NOT actually exclude a target presented as "
    "'xn--mnchen-3ya.de'. See docs/SAFETY_MODEL.md / ARCHITECTURE.md."
))
def test_idna_punycode_equivalence_not_yet_recognized():
    assert scope_check.matches("xn--mnchen-3ya.de", "münchen.de")


@pytest.mark.xfail(reason=(
    "Wildcard exclusion syntax is not supported: an exclusion entry like "
    "'*.internal.example.com' matches NOTHING today, including the exact "
    "subdomains it looks like it should exclude. This is a silent no-op, "
    "not a parse error -- an operator could believe internal hosts are "
    "excluded from testing when they are not. Real safety concern, not "
    "just a missing convenience feature -- flag before relying on wildcard "
    "exclusions in any real engagement's scope.yml."
))
def test_wildcard_exclusion_currently_silently_matches_nothing():
    assert scope_check.matches("api.internal.example.com", "*.internal.example.com")