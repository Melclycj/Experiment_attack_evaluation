"""Credential records (validation.md K-10, K-30, K-32; 648d60f2 4.3 凭据)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from engine.credentials import CredentialStore
from engine.matching import Endpoint, Placement
from engine.workspaces import Disk, EntryInvalid


def store(tmp_path: Path, disk: Disk | None = None) -> CredentialStore:
    s = CredentialStore(tmp_path / 'state', disk)
    s.load()
    return s


def test_register_endpoints_and_files(tmp_path: Path) -> None:
    s = store(tmp_path)
    r = s.register('api.github.com:443', 'alice', 2, b'token', b'ghp_secret', b'',
                   token_endpoint='https://github.com/login/oauth/access_token')
    assert (r.placement, r.word, r.generation, r.has_truth_b) == (Placement.AUTHORIZATION_BEARER, b'token', 1, False)
    assert s.endpoints_of({('api.github.com:443', 'alice')}) == {Endpoint('github.com:443', '/login/oauth/access_token')}
    assert s.endpoints_of({('api.github.com:443', 'bob')}) == set()                 # another account's are not its
    d = tmp_path / 'state' / 'credentials' / 'api.github.com:443'
    assert sorted(p.name for p in d.iterdir()) == ['alice.1.truth_a', 'alice.json']
    assert oct(os.stat(d).st_mode & 0o777) == '0o700' and all(oct(os.stat(p).st_mode & 0o777) == '0o600' for p in d.iterdir())
    assert b'ghp_secret' not in (d / 'alice.json').read_bytes()            # metadata holds no truth
    assert repr(s.records).find('ghp_secret') < 0
    assert not hasattr(s, 'index')                                         # K-32: no placeholder index any more
    again = store(tmp_path)                                                # survives a restart
    assert again.records == s.records and again.broken == []


def test_truths_are_read_by_the_key_and_the_account(tmp_path: Path) -> None:
    s = store(tmp_path)
    s.register('git.example:443', 'bob', 3, b'', b'bob-user', b'bob-pass')
    a, b = s.read_truths('git.example:443', 'bob')
    assert isinstance(a, bytearray) and bytes(a) == b'bob-user' and bytes(b) == b'bob-pass'
    for buf in (a, b):
        buf[:] = bytes(len(buf))
    assert bytes(a) == b'\0' * 8
    with pytest.raises(EntryInvalid):
        s.read_truths('git.example:443', 'carol')
    s.register('api.example:443', 'key', 1, b'', b'k', b'')
    assert [bytes(x) for x in s.read_truths('api.example:443', 'key')] == [b'k', b'']


def test_registration_validation(tmp_path: Path) -> None:
    s = store(tmp_path)
    for bad in (b'a\rb', b'a\nb', b'a\x00b', b'a\x7fb', b'x' * 5000):
        with pytest.raises(EntryInvalid):
            s.register('h:443', 'a', 2, b'Bearer', bad, b'')
    bad_shapes = [
        (3, b'', b'user', b''),                       # Basic needs both
        (3, b'', b'us:er', b'pass'),                  # a Basic user name has no colon
        (2, b'Bearer', b'tok', b'extra'),             # non-Basic has one truth
        (2, b'', b'tok', b''),                        # the bearer placement registers its word
        (2, b'bearer', b'tok', b''),                  # the word is Bearer or token, as written
        (1, b'Bearer', b'tok', b''),                  # the word only on the bearer placement
        (3, b'Basic', b'u', b'p'),
        (9, b'', b'tok', b''),
    ]
    for placement, word, a, b in bad_shapes:
        with pytest.raises(EntryInvalid):
            s.register('h:443', 'a', placement, word, a, b)
    for host_port, account in (('H:443', 'a'), ('h:443', '../x')):
        with pytest.raises(EntryInvalid):
            s.register(host_port, account, 2, b'Bearer', b'tok', b'')
    with pytest.raises(EntryInvalid):
        s.register('h:443', 'a', 2, b'Bearer', b'tok', b'', token_endpoint='ftp://x/y')
    assert s.records == {} and s.version == 0


def test_a_rewrite_replaces_the_whole_record(tmp_path: Path) -> None:
    """K-30 整份生效: a reader sees the whole old record or the whole new one, at every step of the rewrite."""
    s = store(tmp_path)
    s.register('h:443', 'a', 3, b'', b'old-user', b'old-pass')
    assert s.version == 1

    class Crash(Disk):
        def __init__(self, at: int) -> None:
            self.at, self.n = at, 0

        def rename(self, tmp: Path, final: Path) -> None:
            self.n += 1
            if self.n == self.at:
                raise OSError('crash')
            super().rename(tmp, final)

    for at in (1, 2, 3):                              # truth_a, truth_b, metadata
        crashing = CredentialStore(tmp_path / 'state', Crash(at))
        crashing.load()
        with pytest.raises(OSError):
            crashing.register('h:443', 'a', 3, b'', b'new-user', b'new-pass')
        after = store(tmp_path)                       # what a restart reads
        assert [bytes(x) for x in after.read_truths('h:443', 'a')] == [b'old-user', b'old-pass']
    s = store(tmp_path)
    r = s.register('h:443', 'a', 2, b'Bearer', b'new-token', b'')
    assert r.generation == 2 and s.version == 1
    assert [bytes(x) for x in store(tmp_path).read_truths('h:443', 'a')] == [b'new-token', b'']
    names = sorted(p.name for p in (tmp_path / 'state' / 'credentials' / 'h:443').iterdir())
    assert 'a.1.truth_a' not in names and 'a.1.truth_b' not in names and 'a.2.truth_a' in names


def test_delete_and_broken_records(tmp_path: Path) -> None:
    s = store(tmp_path)
    s.register('h:443', 'a', 2, b'Bearer', b'tok', b'', token_endpoint='https://h/token')
    s.register('h:443', 'b', 1, b'', b'key', b'')
    s.delete('h:443', 'a')
    assert ('h:443', 'a') not in s.records and s.endpoints_of({('h:443', 'a')}) == set() and s.version == 3
    assert sorted(p.name for p in (tmp_path / 'state' / 'credentials' / 'h:443').iterdir()) == ['b.1.truth_a', 'b.json']
    with pytest.raises(EntryInvalid):
        s.delete('h:443', 'a')
    (tmp_path / 'state' / 'credentials' / 'h:443' / 'b.1.truth_a').unlink()
    again = store(tmp_path)
    assert again.broken == ['h:443/b.json'] and again.records == {}


class Faults(Disk):
    """Fails the n-th call of a step, counted per step across the whole life of the store."""

    def __init__(self, **at: int) -> None:
        self.at, self.n = at, {step: 0 for step in at}

    def _step(self, step: str) -> None:
        if step in self.at:
            self.n[step] += 1
            if self.n[step] == self.at[step]:
                raise OSError(f'{step} failed')

    def rename(self, tmp: Path, final: Path) -> None:
        self._step('rename')
        super().rename(tmp, final)

    def fsync_dir(self, directory: Path) -> None:
        self._step('fsync_dir')
        super().fsync_dir(directory)


def test_a_failed_rewrite_never_reuses_its_generation(tmp_path: Path) -> None:
    """K-30 整份生效 across a failed attempt: the metadata of the first rewrite reached its name and only the directory
    fsync failed, so the disk already names that generation; a retry that wrote into the same generation and failed
    half way would leave a record that is half the first attempt, half the second (review: Codex)."""
    s = store(tmp_path, Faults(fsync_dir=6, rename=8))       # rewrite 1: the metadata fsync; rewrite 2: its truth_b
    s.register('h:443', 'a', 3, b'', b'old-user', b'old-pass')
    with pytest.raises(OSError):
        s.register('h:443', 'a', 3, b'', b'user-1', b'pass-1')
    with pytest.raises(OSError):
        s.register('h:443', 'a', 3, b'', b'user-2', b'pass-2')
    after = [bytes(x) for x in store(tmp_path).read_truths('h:443', 'a')]
    assert after in ([b'old-user', b'old-pass'], [b'user-1', b'pass-1'], [b'user-2', b'pass-2'])


def test_the_old_truth_left_behind_does_not_undo_a_rewrite_or_a_delete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """K-31: once the new record is in effect the caller must learn of it, so the connections are cut; removing the old
    generation's files is cleanup, and a failure there is reported, not raised (review: Codex)."""
    s = store(tmp_path)
    s.register('h:443', 'a', 2, b'Bearer', b'tok-1', b'')
    real_unlink = Path.unlink

    def unlink(self: Path, missing_ok: bool = False) -> None:
        if '.truth_' in self.name and self.exists():
            raise PermissionError('unlink refused')
        real_unlink(self, missing_ok)

    monkeypatch.setattr(Path, 'unlink', unlink)
    r = s.register('h:443', 'a', 2, b'Bearer', b'tok-2', b'')
    assert r.generation == 2 and s.records[('h:443', 'a')] == r and s.version == 2
    assert [bytes(x) for x in s.read_truths('h:443', 'a')] == [b'tok-2', b'']
    assert s.leftover == ['h:443/a.1.truth_a']
    s.delete('h:443', 'a')
    assert ('h:443', 'a') not in s.records and s.version == 3
    assert s.leftover[1:] == ['h:443/a.1.truth_a', 'h:443/a.2.truth_a']
    monkeypatch.undo()
    assert store(tmp_path).records == {}


def test_a_failed_attempts_truth_goes_with_the_next_change(tmp_path: Path) -> None:
    """A failed rewrite leaves its generation's truth files (that generation is never written again); the next rewrite
    or delete that takes effect removes them with the rest, and another account whose name extends this one keeps its
    own (cold recheck 2026-11-01)."""
    s = store(tmp_path, Faults(fsync_dir=8))                 # the first rewrite of a fails at its metadata fsync
    s.register('h:443', 'a', 3, b'', b'old-user', b'old-pass')
    s.register('h:443', 'a.1', 2, b'Bearer', b'other', b'')
    with pytest.raises(OSError):
        s.register('h:443', 'a', 3, b'', b'user-1', b'pass-1')
    s.register('h:443', 'a', 3, b'', b'user-2', b'pass-2')
    d = tmp_path / 'state' / 'credentials' / 'h:443'
    assert sorted(p.name for p in d.iterdir() if p.name.startswith('a.') and '.truth_' in p.name) ==         ['a.1.1.truth_a', 'a.3.truth_a', 'a.3.truth_b']
    s.delete('h:443', 'a')
    assert sorted(p.name for p in d.iterdir()) == ['a.1.1.truth_a', 'a.1.json'] and s.leftover == []
