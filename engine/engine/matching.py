"""Matching a judged request against a workspace table (agent-rm-model 3.2 格子的键与匹配, 4.3 凭据, 5.3 条款 9 and 10;
validation.md K-06, K-07, K-08, K-09, K-25, K-26, K-43, K-44).

Pure functions over the request's canonical fields and the table's entries: nothing here reads a socket, a file or a
clock, and nothing here selects a row or a table (K-35): the caller hands in the entries of the row's own workspace.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from .workspaces import Approval, Entry, EntryInvalid, EntryState, KeyKind, check_host_port, check_prefix


class Outcome(Enum):
    DENY_RECORDED = 'deny_recorded'     # a recorded deny covers the request at some key level (条款 9, K-43 step 1)
    ALLOW_RECORDED = 'allow_recorded'   # the most specific key's allow entry covers it; approval mode decides asking
    NO_RECORD = 'no_record'             # nothing covers it: ask the user (3.7 默认规则)


@dataclass(frozen=True)
class Match:
    outcome: Outcome
    entry: Entry | None                 # the covering entry (deny or allow); None for NO_RECORD
    key_kind: KeyKind | None            # the most specific key level that exists for this destination
    key: str | None


class Placement(Enum):
    X_API_KEY = 1
    AUTHORIZATION_BEARER = 2            # Authorization: <registered word> <truth>, the word Bearer or token
    AUTHORIZATION_BASIC = 3             # Authorization: Basic base64(<registered user>:<registered password>)


HEADER_OF = {Placement.X_API_KEY: b'x-api-key', Placement.AUTHORIZATION_BEARER: b'authorization',
             Placement.AUTHORIZATION_BASIC: b'authorization'}
CREDENTIAL_HEADERS = frozenset(HEADER_OF.values())


@dataclass(frozen=True)
class Binding:
    """The credential the engine attaches to one request (648d60f2 4.3 凭据; K-09, K-44): one account's record and its
    registered placement. Computed from the matched entry, the start-time designation and the records, never from
    request bytes beyond the header names."""

    host_port: str
    account: str
    placement: Placement


class CredentialRefused(Exception):
    """The request carries a credential header and no usable credential record exists for it (648d60f2 4.3 凭据)."""


# ---- keys (K-06) ----------------------------------------------------------------------------------------------------
def exact_key(host: bytes, port: int) -> str:
    return f'{host.decode("ascii")}:{port}'


def pattern_candidates(entries: Mapping[tuple[KeyKind, str], Entry], host: bytes, port: int) -> list[Entry]:
    """Pattern entries whose suffix the host ends with (as ``.suffix``, the apex itself does not count) at this port,
    longest suffix first."""
    text = host.decode('ascii')
    hits = []
    for (kind, key), entry in entries.items():
        if kind is not KeyKind.PATTERN:
            continue
        suffix, _, key_port = key.rpartition(':')
        if int(key_port) == port and text.endswith('.' + suffix) and len(text) > len(suffix) + 1:
            hits.append((len(suffix), entry))
    hits.sort(key=lambda h: -h[0])
    return [e for _, e in hits]


def heir(entries: Mapping[tuple[KeyKind, str], Entry], identity: tuple[KeyKind, str]) -> Entry | None:
    """The entry that decides the destinations of the key ``identity`` once that key is gone: the longest coarser
    pattern at the same port, else the fallback (K-43: no fallback to a coarser key while a more specific one exists)."""
    kind, key = identity
    if kind is KeyKind.FALLBACK:
        return None
    host, _, port = key.rpartition(':')
    rest = {i: e for i, e in entries.items() if i != identity}
    coarser = pattern_candidates(rest, host.encode('ascii'), int(port))
    return coarser[0] if coarser else rest.get((KeyKind.FALLBACK, ''))


def levels(entries: Mapping[tuple[KeyKind, str], Entry], host: bytes, port: int) -> list[tuple[KeyKind, str, Entry]]:
    """The entries that name this destination, most specific first: the exact entry, the longest matching pattern,
    the fallback. One entry per level in this build (one entry per key)."""
    out: list[tuple[KeyKind, str, Entry]] = []
    exact = entries.get((KeyKind.EXACT, exact_key(host, port)))
    if exact is not None:
        out.append((KeyKind.EXACT, exact.key, exact))
    patterns = pattern_candidates(entries, host, port)
    if patterns:
        out.append((KeyKind.PATTERN, patterns[0].key, patterns[0]))
    fallback = entries.get((KeyKind.FALLBACK, ''))
    if fallback is not None:
        out.append((KeyKind.FALLBACK, '', fallback))
    return out


# ---- coverage (K-05 prefixes on segment boundaries, K-43) --------------------------------------------------------------
def path_under(path: str, prefix: str) -> bool:
    """``prefix`` covers ``path`` when equal or a parent on a segment boundary: /repos/a covers /repos/a/x, not /repos/ab.
    A single trailing slash on either side does not matter (K-25 读法放宽)."""
    p = path if path == '/' else path.rstrip('/')
    q = prefix if prefix == '/' else prefix.rstrip('/')
    return q == '/' or p == q or p.startswith(q + '/')


def covers(entry: Entry, method: bytes, path: bytes) -> bool:
    m, p = method.decode('ascii'), path.decode('ascii')
    if entry.methods and m not in entry.methods:
        return False
    return not entry.prefixes or any(path_under(p, prefix) for prefix in entry.prefixes)


def match(entries: Mapping[tuple[KeyKind, str], Entry], host: bytes, port: int, method: bytes, path: bytes) -> Match:
    """K-43 two steps: any covering deny at any level refuses without asking (条款 9 cross-key deny first); otherwise the
    most specific existing key decides: its allow entry covering the request allows it (approval mode applies), a key
    that exists without covering means "no record" (ask), with no fallback to a coarser key (reading one)."""
    found = levels(entries, host, port)
    # step 1 looks at every entry naming this destination, every matching pattern included: a broader pattern's deny is
    # not hidden by a narrower pattern's allow (条款 9 记录过禁止优先; review B, B4)
    everything = list(found) + [(KeyKind.PATTERN, e.key, e) for e in pattern_candidates(entries, host, port)[1:]]
    for kind, key, entry in everything:
        if entry.state is EntryState.DENY and covers(entry, method, path):
            return Match(Outcome.DENY_RECORDED, entry, kind, key)
    if not found:
        return Match(Outcome.NO_RECORD, None, None, None)
    kind, key, entry = found[0]
    if entry.state is EntryState.ALLOW and covers(entry, method, path):
        return Match(Outcome.ALLOW_RECORDED, entry, kind, key)
    return Match(Outcome.NO_RECORD, None, kind, key)


# ---- the credential of a request (K-09, K-26, K-44) ----------------------------------------------------------------------------
def chosen_account(entry: Entry, bound: str | None) -> str | None:
    """3.1: the account the user designated at start for this destination while the entry still lists it, else the
    entry's only account; accounts sit on exact entries only."""
    accounts = entry.accounts if entry.key_kind is KeyKind.EXACT else frozenset()
    if bound is not None:
        return bound if bound in accounts else None
    return next(iter(accounts)) if len(accounts) == 1 else None


def credential_for(entry: Entry, key: str, scheme: bytes, headers: tuple[tuple[bytes, bytes], ...],
                   records: Mapping[tuple[str, str], Any], bound: str | None = None) -> Binding | None:
    """648d60f2 4.3 凭据 on an allow entry. The account: the one the user designated for this destination at start
    (``bound``), refused when it is no longer among the entry's accounts; else the entry's only account, read live.
    Whether the request carries a credential header looks at header names only: the selected account's registered
    placement when it has a record, otherwise either of x-api-key and authorization. A request that carries one and has
    no usable record is refused; one that carries none goes without a credential. Over plain http no truth is ever
    released (条款 4): the header goes as it is. ``records`` maps (host_port, account) to records with a placement."""
    account = chosen_account(entry, bound) if entry.key == key else None
    record = records.get((key, account)) if account is not None else None
    names = {name for name, _ in headers}
    if record is not None:
        carried = HEADER_OF[record.placement] in names
    else:
        carried = bool(names & CREDENTIAL_HEADERS)
    if not carried:
        return None
    if record is None:
        raise CredentialRefused('the request carries a credential header and no usable credential record exists')
    if scheme != b'https':
        return None                                   # K-26 / 条款 4: allowed without credential, nothing replaced
    return Binding(key, account, record.placement)    # type: ignore[arg-type]


# ---- 条款 10 (K-25): token-request shapes and registered endpoints ----------------------------------------------------------
GRANT_TYPE = 'grant_type'


def token_form(method: bytes, body_kind: str, form_keys: tuple[str, ...]) -> bool:
    # the canonical method is case-sensitive and goes out as written; an upstream may still read "post" as POST
    return method.upper() == b'POST' and body_kind == 'application/x-www-form-urlencoded' and GRANT_TYPE in form_keys


@dataclass(frozen=True)
class Endpoint:
    host_port: str
    path: str                     # normalised, without a single trailing slash

    @classmethod
    def parse(cls, url: str) -> Endpoint:
        """A registered OAuth endpoint (token_endpoint, registration_endpoint, device_authorization_endpoint) read into the
        same host:port and path spelling the connector produces, so equality is a byte comparison (K-25)."""
        parts = urlsplit(url)
        if parts.scheme not in ('http', 'https') or not parts.hostname:
            raise EntryInvalid('endpoint is not an http(s) URL')
        port = parts.port or (443 if parts.scheme == 'https' else 80)
        host_port = check_host_port(f'{parts.hostname.lower()}:{port}')
        return cls(host_port, check_prefix(parts.path or '/'))


def usable_accounts(entries: Iterable[Entry], designated: Mapping[str, str]) -> set[tuple[str, str]]:
    """条款 10 (design 2026-11-02): the (host_port, account) pairs a row's credential binding can take, one per exact
    entry, chosen as credential_for chooses. Only their records' endpoints are the row's 条款 10 list, so a refusal
    never depends on another row's or another workspace's accounts."""
    pairs = ((e.key, chosen_account(e, designated.get(e.key))) for e in entries)
    return {(key, account) for key, account in pairs if account is not None}


def endpoint_hit(host: bytes, port: int, path: bytes, endpoints: frozenset[Endpoint] | set[Endpoint]) -> bool:
    p = path.decode('ascii')
    p = p if p == '/' else p.rstrip('/')
    return Endpoint(exact_key(host, port), p) in endpoints
