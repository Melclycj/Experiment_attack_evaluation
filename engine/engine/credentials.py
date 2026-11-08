"""Credential records (agent-rm-model 648d60f2 4.3 凭据; build plan 工程项 6; validation.md K-10, K-26, K-30, K-32).

Metadata (placement, the authorization word, the generation, OAuth endpoints) lives in
``state/credentials/<host_port>/<account>.json``; the truth values live beside it as raw byte files of that generation
(``<account>.<gen>.truth_a``, and ``.truth_b`` for the Basic password), all 0600 in 0700 directories. A rewrite writes
the new generation's truth files first and the metadata last, so a reader sees the whole old record or the whole new one
(K-30). Both path segments come from the matched entry's key and the selected account, never from request bytes (K-10).
Truth is read with ``readv`` into caller-owned bytearrays the caller zeroes after use. The records' endpoints, kept in
memory, hold no truth (K-32). ``version`` grows on every change and is never reused within a run (K-46).
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any, Iterable

from .matching import Endpoint, Placement
from .workspaces import Disk, EntryInvalid, check_account, check_host_port

TRUTH_MAX = 4096
WORDS = (b'Bearer', b'token')              # the registered authorization word of the bearer placement
META_KEYS = {'v', 'account', 'host_port', 'placement', 'word', 'generation', 'token_endpoint', 'registration_endpoint',
             'device_authorization_endpoint', 'has_truth_b'}


def check_truth(value: bytes, name: str) -> bytes:
    """K-30: no CR, LF, other control bytes or DEL; every byte is latin-1 by construction. Empty is allowed only where the
    layout says so (the caller decides)."""
    if len(value) > TRUTH_MAX or any(c < 0x20 or c == 0x7F for c in value):
        raise EntryInvalid(f'{name} has a control character or exceeds {TRUTH_MAX} bytes')
    return value


def check_word(place: Placement, word: bytes) -> bytes:
    """K-30: the bearer placement registers its word, Bearer or token; the other placements register none."""
    if place is Placement.AUTHORIZATION_BEARER:
        if word not in WORDS:
            raise EntryInvalid('the bearer placement registers the word Bearer or token')
    elif word:
        raise EntryInvalid('only the bearer placement registers an authorization word')
    return word


@dataclass(frozen=True)
class CredentialRecord:
    host_port: str
    account: str
    placement: Placement
    word: bytes
    generation: int
    endpoints: frozenset[Endpoint]
    has_truth_b: bool

    def to_json(self, urls: tuple[str, str, str]) -> dict[str, Any]:
        return {'v': 2, 'account': self.account, 'host_port': self.host_port, 'placement': int(self.placement.value),
                'word': self.word.decode('ascii'), 'generation': self.generation, 'token_endpoint': urls[0],
                'registration_endpoint': urls[1], 'device_authorization_endpoint': urls[2], 'has_truth_b': self.has_truth_b}


class CredentialStore:
    def __init__(self, state_dir: Path, disk: Disk | None = None) -> None:
        self.directory = Path(state_dir) / 'credentials'
        self.disk = disk or Disk()
        self.records: dict[tuple[str, str], CredentialRecord] = {}
        self.broken: list[str] = []                                    # records that did not read at start
        self.leftover: list[str] = []                                  # old truth files a change could not remove
        self.attempted: dict[tuple[str, str], int] = {}                # the last generation a rewrite wrote into
        self.version = 0                                               # +1 on every change (K-46)

    # ---- start ----
    def load(self) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        for host_dir in sorted(p for p in self.directory.iterdir() if p.is_dir()):
            for meta in sorted(host_dir.glob('*.json')):
                try:
                    record = self._read_meta(meta, host_dir.name)
                    self.records[(record.host_port, record.account)] = record
                except (OSError, ValueError, EntryInvalid):
                    self.broken.append(f'{host_dir.name}/{meta.name}')

    def _read_meta(self, meta: Path, host_dir: str) -> CredentialRecord:
        d = json.loads(meta.read_bytes())
        if (not isinstance(d, dict) or set(d) != META_KEYS or d['v'] != 2 or not isinstance(d['has_truth_b'], bool)
                or type(d['generation']) is not int or d['generation'] < 1 or not isinstance(d['word'], str)):
            raise EntryInvalid('credential metadata has the wrong shape')
        host_port = check_host_port(d['host_port'])
        account = check_account(d['account'])
        if host_port != host_dir or account != meta.stem:
            raise EntryInvalid('credential metadata names another record')
        urls = (d['token_endpoint'], d['registration_endpoint'], d['device_authorization_endpoint'])
        if not all(isinstance(u, str) for u in urls):
            raise EntryInvalid('endpoint is not a string')
        place = Placement(d['placement'])
        record = CredentialRecord(host_port, account, place, check_word(place, d['word'].encode('ascii')), d['generation'],
                                  frozenset(Endpoint.parse(u) for u in urls if u), d['has_truth_b'])
        if record.has_truth_b is not (place is Placement.AUTHORIZATION_BASIC):
            raise EntryInvalid('credential metadata has the wrong shape')
        if not self._truth_path(record, 'a').exists() or (record.has_truth_b and not self._truth_path(record, 'b').exists()):
            raise EntryInvalid('truth file missing')
        return record

    def _truth_path(self, record: CredentialRecord, part: str) -> Path:
        return self.directory / record.host_port / f'{record.account}.{record.generation}.truth_{part}'

    def endpoints_of(self, accounts: Iterable[tuple[str, str]]) -> set[Endpoint]:
        """The OAuth endpoints registered on these accounts' records: 条款 10 takes a row's own (design 2026-11-02)."""
        return {e for key in accounts if (r := self.records.get(key)) is not None for e in r.endpoints}

    # ---- registration (管理口 CRED_PUT, K-30) ----
    def register(self, host_port: str, account: str, placement: int, word: bytes, truth_a: bytes, truth_b: bytes,
                 token_endpoint: str = '', registration_endpoint: str = '', device_authorization_endpoint: str = '') -> CredentialRecord:
        """Returns the new record; the caller learns whether it replaced one by looking before (K-31)."""
        host_port, account = check_host_port(host_port), check_account(account)
        try:
            place = Placement(placement)
        except ValueError:
            raise EntryInvalid('unknown placement') from None
        check_word(place, word)
        check_truth(truth_a, 'truth_a')
        check_truth(truth_b, 'truth_b')
        if place is Placement.AUTHORIZATION_BASIC:
            if not truth_a or not truth_b:
                raise EntryInvalid('Basic needs both the user and the password truth')
            if b':' in truth_a:
                raise EntryInvalid('a Basic user name has no colon (RFC 7617)')
        elif not truth_a or truth_b:
            raise EntryInvalid('non-Basic placement has one truth, in truth_a')
        urls = (token_endpoint, registration_endpoint, device_authorization_endpoint)
        old = self.records.get((host_port, account))
        # a generation is written into at most once per run: a failed attempt may already be named on disk (its metadata
        # renamed, the directory fsync failed), and a retry into it could leave half of each attempt (K-30)
        generation = max(old.generation if old else 0, self.attempted.get((host_port, account), 0)) + 1
        self.attempted[(host_port, account)] = generation
        record = CredentialRecord(host_port, account, place, word, generation,
                                  frozenset(Endpoint.parse(u) for u in urls if u), place is Placement.AUTHORIZATION_BASIC)
        host_dir = self.directory / host_port
        host_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(host_dir, 0o700)
        # the new generation's truth files first (0600, fsync), the metadata naming them last: a crash before the
        # metadata leaves the old record whole; after it, the new one (K-30 整份生效)
        self._write_file(self._truth_path(record, 'a'), truth_a)
        if record.has_truth_b:
            self._write_file(self._truth_path(record, 'b'), truth_b)
        self._write_file(host_dir / f'{account}.json',
                         json.dumps(record.to_json(urls), separators=(',', ':'), sort_keys=True).encode())
        self.records[(host_port, account)] = record
        self.version += 1
        self._remove_stale(host_port, account, record.generation)
        return record

    def _write_file(self, final: Path, data: bytes) -> None:
        tmp = final.with_name(final.name + '.tmp')
        self.disk.write_tmp(tmp, data)
        self.disk.rename(tmp, final)
        self.disk.fsync_dir(final.parent)

    def _remove_stale(self, host_port: str, account: str, keep: int | None) -> None:
        """Cleanup after the change took effect: every truth file of the account but the generation its metadata now
        names, those of failed attempts included. A file that will not go is kept in ``leftover`` for the caller to
        report, never raised, so the caller still cuts the connections the change ends (K-31)."""
        host_dir, prefix = self.directory / host_port, account + '.'
        try:
            names = sorted(p.name for p in host_dir.iterdir())
        except OSError:
            self.leftover.append(f'{host_port}/{account}.*')
            return
        for name in names:
            # <account>.<generation>.truth_<a|b>; an account name may hold dots, the generation is ASCII digits
            gen, _, part = name[len(prefix):].partition('.') if name.startswith(prefix) else ('', '', '')
            if not (gen.isascii() and gen.isdigit() and part in ('truth_a', 'truth_b')) or int(gen) == keep:
                continue
            try:
                (host_dir / name).unlink()
            except FileNotFoundError:
                pass
            except OSError:
                self.leftover.append(f'{host_port}/{name}')

    def delete(self, host_port: str, account: str) -> None:
        record = self.records.get((host_port, account))
        if record is None:
            raise EntryInvalid('no such credential record')
        try:
            (self.directory / host_port / f'{account}.json').unlink()       # the record is gone from here on
        except FileNotFoundError:
            pass
        del self.records[(host_port, account)]
        self.version += 1
        self._remove_stale(host_port, account, None)

    # ---- the one read path (K-10) ----
    def read_truths(self, host_port: str, account: str) -> tuple[bytearray, bytearray]:
        """The record's truths, each in a fresh bytearray: the truth (or the Basic user name) and the Basic password
        (empty for the other placements). The caller zeroes both after writing them into the ALLOW frame."""
        record = self.records.get((host_port, account))
        if record is None:
            raise EntryInvalid('no such credential record')
        a = self._read(self._truth_path(record, 'a'))
        try:
            b = self._read(self._truth_path(record, 'b')) if record.has_truth_b else bytearray()
        except BaseException:
            a[:] = bytes(len(a))
            raise
        return a, b

    @staticmethod
    def _read(path: Path) -> bytearray:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            size = os.fstat(fd).st_size
            if size > TRUTH_MAX:
                raise EntryInvalid('truth file too large')
            out = bytearray(size)
            view, got = memoryview(out), 0
            while got < size:
                n = os.readv(fd, [view[got:]])
                if n <= 0:
                    out[:] = bytes(size)
                    raise EntryInvalid('truth file short read')
                got += n
            return out
        finally:
            os.close(fd)
