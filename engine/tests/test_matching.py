"""Matching (validation.md K-06, K-07, K-08, K-09, K-25, K-26, K-43, K-44): table-driven."""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from engine import matching as m
from engine.matching import CredentialRefused, Endpoint, Outcome, Placement
from engine.workspaces import FALLBACK_DEFAULT, Approval, EntryState, KeyKind, make_entry


def allow(key, methods=(), prefixes=(), accounts=(), approval=Approval.NEVER, kind=KeyKind.EXACT):
    return make_entry(kind, key, EntryState.ALLOW, methods, prefixes, accounts, approval)


def deny(key, methods=(), prefixes=(), kind=KeyKind.EXACT):
    return make_entry(kind, key, EntryState.DENY, methods, prefixes, (), Approval.NEVER)


def table(*entries):
    return {e.identity: e for e in entries}


def match(entries, host=b'api.github.com', port=443, method=b'GET', path=b'/repos/a'):
    return m.match(entries, host, port, method, path)


# ---- K-06 keys -----------------------------------------------------------------------------------------------------------
def test_exact_pattern_and_fallback_levels() -> None:
    t = table(allow('api.github.com:443'), allow('github.com:443', kind=KeyKind.PATTERN),
              allow('com:443', kind=KeyKind.PATTERN), FALLBACK_DEFAULT)
    lv = m.levels(t, b'api.github.com', 443)
    assert [(k, key) for k, key, _ in lv] == [(KeyKind.EXACT, 'api.github.com:443'), (KeyKind.PATTERN, 'github.com:443'),
                                              (KeyKind.FALLBACK, '')]
    assert [key for _, key, _ in m.levels(t, b'x.github.com', 443)] == ['github.com:443', '']      # longest suffix
    assert [key for _, key, _ in m.levels(t, b'github.com', 443)] == ['com:443', '']                # apex is not a hit
    assert [key for _, key, _ in m.levels(t, b'api.github.com', 80)] == ['']                        # port differs
    assert [key for _, key, _ in m.levels(t, b'apigithub.com', 443)] == ['com:443', '']            # needs the dot
    assert m.levels({}, b'x', 443) == []


# ---- K-05 prefixes on segment boundaries -------------------------------------------------------------------------------------
@pytest.mark.parametrize('path,prefix,hit', [('/repos/a', '/repos/a', True), ('/repos/a/x', '/repos/a', True),
                                              ('/repos/ab', '/repos/a', False), ('/repos', '/repos/a', False),
                                              ('/repos/a/', '/repos/a', True), ('/repos/a', '/repos/a/', True),
                                              ('/anything', '/', True), ('/', '/', True), ('/', '/a', False)])
def test_prefix_segment_boundary(path: str, prefix: str, hit: bool) -> None:
    assert m.path_under(path, prefix) is hit


# ---- K-07 / K-43 priority and the two steps -----------------------------------------------------------------------------------
def test_recorded_deny_at_any_level_wins_without_asking() -> None:
    # the mandated cross-level counterexample: pattern denies GET /public, exact allows the same request and never asks
    t = table(deny('github.com:443', ('GET',), ('/public',), kind=KeyKind.PATTERN),
              allow('api.github.com:443', ('GET',), ('/public',), approval=Approval.NEVER), FALLBACK_DEFAULT)
    r = match(t, path=b'/public/x')
    assert r.outcome is Outcome.DENY_RECORDED and r.key_kind is KeyKind.PATTERN
    # a deny with a method limit refuses only that method; the other request falls to the exact allow
    assert match(t, method=b'POST', path=b'/public/x').outcome is Outcome.NO_RECORD        # exact allows GET only
    # one entry per key: a method-limited deny lives on another level than the allow it overrides
    t2 = table(deny('github.com:443', ('DELETE',), kind=KeyKind.PATTERN), allow('api.github.com:443', ('GET', 'DELETE')), FALLBACK_DEFAULT)
    assert match(t2, method=b'DELETE').outcome is Outcome.DENY_RECORDED
    assert match(t2, method=b'GET').outcome is Outcome.ALLOW_RECORDED
    # fallback covered by a recorded exact deny
    t3 = table(deny('evil.example:443'), FALLBACK_DEFAULT)
    assert match(t3, host=b'evil.example').outcome is Outcome.DENY_RECORDED


def test_most_specific_key_decides_and_no_fallback_to_coarser_keys() -> None:
    t = table(allow('api.github.com:443', ('GET',), ('/repos',)), allow('github.com:443', kind=KeyKind.PATTERN), FALLBACK_DEFAULT)
    assert match(t).outcome is Outcome.ALLOW_RECORDED
    # the exact key exists but does not cover: no record, and no fall back to the pattern or the fallback (reading one)
    r = match(t, method=b'POST')
    assert r.outcome is Outcome.NO_RECORD and r.key_kind is KeyKind.EXACT and r.entry is None
    r = match(t, path=b'/users/a')
    assert r.outcome is Outcome.NO_RECORD and r.key_kind is KeyKind.EXACT
    # a host under the pattern only: pattern decides
    assert match(t, host=b'raw.github.com', method=b'POST').outcome is Outcome.ALLOW_RECORDED   # pattern: any method
    # unknown host: fallback GET allowed, POST asks (K-08)
    assert match(t, host=b'unknown.example').outcome is Outcome.ALLOW_RECORDED
    r = match(t, host=b'unknown.example', method=b'POST')
    assert r.outcome is Outcome.NO_RECORD and r.key_kind is KeyKind.FALLBACK
    # no fallback entry at all: nothing covers, ask
    r = match(table(allow('other:443')), host=b'unknown.example')
    assert r.outcome is Outcome.NO_RECORD and r.key_kind is None


def test_approval_mode_rides_on_the_matched_entry() -> None:
    t = table(allow('api.github.com:443', ('GET',), approval=Approval.ALWAYS))
    r = match(t)
    assert r.outcome is Outcome.ALLOW_RECORDED and r.entry.approval is Approval.ALWAYS


# ---- K-09 / K-26 / K-44 credentials (648d60f2 4.3 凭据) -------------------------------------------------------------------------
@dataclass(frozen=True)
class Rec:
    placement: Placement


GH = 'api.github.com:443'
RECORDS = {(GH, 'alice'): Rec(Placement.AUTHORIZATION_BEARER), (GH, 'carol'): Rec(Placement.AUTHORIZATION_BEARER),
           ('api.anthropic.com:443', 'work'): Rec(Placement.X_API_KEY),
           ('git.example:443', 'bob'): Rec(Placement.AUTHORIZATION_BASIC)}
BEARER = ((b'authorization', b'Bearer anything'),)


def cred(entry, key, headers, scheme=b'https', bound=None, records=RECORDS):
    return m.credential_for(entry, key, scheme, headers, records, bound)


def test_three_placements_are_found_by_header_name() -> None:
    work = cred(allow('api.anthropic.com:443', accounts=('work',)), 'api.anthropic.com:443', ((b'x-api-key', b'x'),))
    assert work == m.Binding('api.anthropic.com:443', 'work', Placement.X_API_KEY)
    assert cred(allow(GH, accounts=('alice',)), GH, BEARER) == m.Binding(GH, 'alice', Placement.AUTHORIZATION_BEARER)
    # the value is never read: a Basic value that does not decode still carries the header
    bob = cred(allow('git.example:443', accounts=('bob',)), 'git.example:443', ((b'authorization', b'Basic !!!'),))
    assert bob == m.Binding('git.example:443', 'bob', Placement.AUTHORIZATION_BASIC)


def test_with_a_record_only_its_registered_placement_counts() -> None:
    e = allow('api.anthropic.com:443', accounts=('work',))
    assert cred(e, 'api.anthropic.com:443', BEARER) is None                 # authorization goes as it is, no credential
    assert cred(e, 'api.anthropic.com:443', ()) is None


def test_without_a_record_either_header_counts_and_is_refused() -> None:
    public = allow(GH)
    for headers in (BEARER, ((b'x-api-key', b'x'),)):
        with pytest.raises(CredentialRefused):                                # no selected account
            cred(public, GH, headers)
        with pytest.raises(CredentialRefused):                                # selected account without a record
            cred(allow(GH, accounts=('dave',)), GH, headers)
    assert cred(public, GH, ((b'x-other', b'v'),)) is None                    # no credential header: goes without one
    with pytest.raises(CredentialRefused):                                    # a pattern entry has no account (条款 5)
        cred(allow('github.com:443', kind=KeyKind.PATTERN), 'github.com:443', BEARER)


def test_plain_http_never_carries_truth() -> None:
    assert cred(allow(GH, accounts=('alice',)), GH, BEARER, scheme=b'http') is None   # K-26: header goes as it is
    with pytest.raises(CredentialRefused):                                    # still refused without a record
        cred(allow(GH), GH, BEARER, scheme=b'http')


def test_request_bytes_never_choose_the_account() -> None:
    """A placeholder or any value of another account changes nothing: only header names are looked at."""
    single = allow(GH, accounts=('alice',))
    for value in (b'Bearer carols-placeholder', b'token carols-placeholder', b'Basic Y2Fyb2w6eA=='):
        assert cred(single, GH, ((b'authorization', value),)).account == 'alice'


def test_one_account_per_destination_chosen_at_start() -> None:
    """K-44 (648d60f2 3.1): the designation wins; refused when it left the entry, never replaced by the rest; without
    one, the entry's only account read live; several and none designated, a carried header is refused."""
    several = allow(GH, accounts=('alice', 'carol'))
    assert cred(several, GH, BEARER, bound='alice').account == 'alice'
    assert cred(several, GH, BEARER, bound='carol').account == 'carol'
    with pytest.raises(CredentialRefused):
        cred(several, GH, BEARER)
    assert cred(several, GH, ()) is None                                      # no header: goes without a credential
    narrowed = allow(GH, accounts=('alice',))                                 # carol designated, then taken off the entry
    with pytest.raises(CredentialRefused):
        cred(narrowed, GH, BEARER, bound='carol')
    assert cred(narrowed, GH, (), bound='carol') is None
    assert cred(allow(GH, accounts=('alice',)), GH, BEARER).account == 'alice'
    assert cred(allow(GH, accounts=('carol',)), GH, BEARER).account == 'carol'    # the entry changed: read live


# ---- K-25 条款 10 --------------------------------------------------------------------------------------------------------------
def test_token_form_and_endpoints() -> None:
    assert m.token_form(b'POST', 'application/x-www-form-urlencoded', ('grant_type', 'code'))
    assert not m.token_form(b'GET', 'application/x-www-form-urlencoded', ('grant_type',))
    assert not m.token_form(b'POST', 'application/json', ('grant_type',))
    assert not m.token_form(b'POST', 'application/x-www-form-urlencoded', ('grant',))
    # overall review 2026-11-03, #17: the canonical method is case-sensitive and sent as written; an upstream that reads
    # a lowercase post as POST must not get a token form past this check
    assert m.token_form(b'post', 'application/x-www-form-urlencoded', ('grant_type',))
    assert m.token_form(b'Post', 'application/x-www-form-urlencoded', ('grant_type',))
    eps = {Endpoint.parse('https://auth.example/oauth/token/'), Endpoint.parse('https://auth.example:8443/register')}
    assert Endpoint.parse('https://auth.example/oauth/token/') == Endpoint('auth.example:443', '/oauth/token')
    assert m.endpoint_hit(b'auth.example', 443, b'/oauth/token', eps)
    assert m.endpoint_hit(b'auth.example', 443, b'/oauth/token/', eps)
    assert not m.endpoint_hit(b'auth.example', 443, b'/oauth/token/x', eps)
    assert not m.endpoint_hit(b'auth.example', 8443, b'/oauth/token', eps)
    assert m.endpoint_hit(b'auth.example', 8443, b'/register', eps)
    with pytest.raises(Exception):
        Endpoint.parse('ftp://auth.example/x')
    with pytest.raises(Exception):
        Endpoint.parse('https://AUTH.example/%41')            # the path grammar applies to registered endpoints too


def test_broader_pattern_deny_is_not_hidden_by_a_narrower_pattern_allow() -> None:
    """条款 9: a recorded prohibition wins at every matching pattern, not only the longest one (review B, B4)."""
    entries = table(deny('test:443', kind=KeyKind.PATTERN), allow('api.test:443', kind=KeyKind.PATTERN))
    got = match(entries, host=b'x.api.test', path=b'/')
    assert got.outcome is Outcome.DENY_RECORDED and got.key == 'test:443'
    # and a narrower pattern's deny still wins over a broader allow
    entries = table(allow('test:443', kind=KeyKind.PATTERN), deny('api.test:443', kind=KeyKind.PATTERN))
    assert match(entries, host=b'x.api.test', path=b'/').outcome is Outcome.DENY_RECORDED
    # without any deny the narrowest pattern still decides
    entries = table(allow('test:443', ('POST',), kind=KeyKind.PATTERN), allow('api.test:443', kind=KeyKind.PATTERN))
    assert match(entries, host=b'x.api.test', path=b'/').outcome is Outcome.ALLOW_RECORDED
