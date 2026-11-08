"""条款 10: the token response, recognised by its body (agent-rm-model 5.3 条款 10; SPEC-canonical-form.md 条款 10 的 token
响应; validation.md C-25, N-16; user ruling 2026-11-04).

An authorization server answers a JSON or bodiless token request as it answers a form, and not every one marks the
answer no-store (2026-11-04 host measurements: Google, GitHub), so neither the request's encoding nor Cache-Control
decides. The response to a POST is a candidate by its media type, and a token response by an access_token in a body
of at most 64 KiB: a top-level key, or in JSON a direct key of a top-level value that is itself an object (Slack's
authed_user; user ruling 2026-11-05). Only these standard shapes are guaranteed (N-16: XML, deeper levels, arrays
pass). A candidate the TCB cannot read as sent is withheld; nothing is decoded here. Pure functions over the response
head and the held body: connector/upstream.py holds the body, asks these and withholds (Exchange._hold, _relay). TCB
module: standard library only.
"""
from __future__ import annotations

import json
from urllib.parse import parse_qsl

from . import canonical
from .canonical import Request

JSON_TYPE = 'application/json'
TOKEN_TYPES = frozenset({JSON_TYPE, canonical.FORM})
TOKEN_LIMIT = 65536                                       # 64 KiB: a token response is small, the upstream a real server
ACCESS_TOKEN = 'access_token'


def field_values(raw: list[tuple[str, str]], name: str) -> list[str]:
    """The values of every field of that name, in order (RFC 9110 §5.3: a repeated name counts every time)."""
    return [value for field, value in raw if field.lower() == name]


def token_candidate(req: Request, raw: list[tuple[str, str]]) -> frozenset[str]:
    """The token media types among the response's Content-Type fields (type/subtype, any case, parameters dropped); empty
    unless the request is a POST in any case (as matching.token_form). The request's own encoding plays no part."""
    if req.method.upper() != b'POST':
        return frozenset()
    named = (value.split(';', 1)[0].strip().lower() for value in field_values(raw, 'content-type'))
    return frozenset(kind for kind in named if kind in TOKEN_TYPES)


def unreadable(raw: list[tuple[str, str]], chunked: bool) -> str:
    """Why a candidate's body is not readable as received, or '' when it is. A content coding other than identity is
    never undone in the TCB (the POST asked for identity). Of the transfer codings http.client undoes chunked alone, and
    only when the one field it reads says exactly that (``chunked``: what it did); any other leaves the bytes coded."""
    codings = [c.strip().lower() for value in field_values(raw, 'content-encoding') for c in value.split(',')]
    if any(c and c != 'identity' for c in codings):          # empty list elements are no coding (RFC 9110 §5.6.1)
        return 'content_encoding'
    transfer = [c.strip().lower() for value in field_values(raw, 'transfer-encoding') for c in value.split(',')]
    transfer = [c for c in transfer if c]
    if transfer and (transfer != ['chunked'] or not chunked):
        return 'transfer_encoding'
    return ''


class Members(list):
    """The members of one JSON object, in order, a repeated name as often as it appears (object_pairs_hook)."""


def names_access_token(members: Members) -> bool:
    """Whether access_token is among one object's member names (a repeated name counts each time it appears)."""
    return any(name == ACCESS_TOKEN for name, _ in members)


def token_body(kinds: frozenset[str], body: bytes) -> bool:
    """Whether a candidate's whole body is a token response: at most 64 KiB and access_token among its keys, as JSON
    (every member name of the top-level object, and of each top-level member's value that is itself an object, all
    collected by object_pairs_hook; arrays, string values and deeper levels are not looked in; json.loads reads the
    bytes as UTF-8, UTF-16 or UTF-32) and as a form (the keys parse_qsl gives, blank values kept), each tried when its
    media type was named. A body that does not parse is not a token response (a residual, N-16)."""
    if len(body) > TOKEN_LIMIT:
        return False
    if JSON_TYPE in kinds:
        try:
            top = json.loads(body, object_pairs_hook=Members)
        except (ValueError, RecursionError):                  # RecursionError: nesting deeper than the parser goes
            top = None
        if isinstance(top, Members) and (names_access_token(top) or any(
                isinstance(value, Members) and names_access_token(value) for _, value in top)):   # a JSON array is
            return True                                                                          # a plain list
    if canonical.FORM in kinds:
        if any(name == ACCESS_TOKEN for name, _ in parse_qsl(body.decode('latin-1'), keep_blank_values=True)):
            return True
    return False
