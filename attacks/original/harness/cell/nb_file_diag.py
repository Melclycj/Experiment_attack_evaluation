"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import errno
import os
from nb_contract import decode


def stat_path(path):
    try:
        s = os.stat(path)
        return {'errno': 0, 'identity': {'dev': s.st_dev, 'ino': s.st_ino, 'size': s.st_size}}
    except OSError as exc:
        return {'errno': exc.errno, 'identity': None}


def diagnostic(result, path, kind, checked):
    """Parse only the diagnostic naming this exact path, never a global substring.
    stat supplies errno ONLY for git's errno-free Could not access diagnostic.
    """
    rc, sig = result['returncode'], result['signal']
    base = {'rc': rc, 'signal': sig, 'errno': None, 'identity': checked['identity'],
            'path': path, 'valid': False, 'stat_errno': checked['errno']}
    if result.get('error') or sig is not None:
        return base
    ok = rc in ((0, 1) if kind in ('git-diff', 'git-output') else (0,))
    stderr = result['stderr'].decode('utf-8', 'replace')
    if ok and not stderr:
        return {**base, 'valid': checked['errno'] == 0, 'errno': 0}
    # A sibling whose name merely begins with path is not this target.
    # Bash names an unquoted path before ': '; git quotes it (possibly
    # followed by ' for writing'). Require both token boundaries.
    def names_target(line):
        return ("'" + path + "'" in line or '"' + path + '"' in line
                or (': ' + path + ': ') in line)
    lines = [line for line in stderr.splitlines() if names_target(line)]
    if len(lines) != 1 or rc == 0:
        return base
    line = lines[0]
    errors = {'No such file or directory': errno.ENOENT, 'Permission denied': errno.EACCES,
              'Read-only file system': errno.EROFS, 'Not a directory': errno.ENOTDIR,
              'Is a directory': errno.EISDIR, 'Too many levels of symbolic links': errno.ELOOP}
    code = next((n for text, n in errors.items() if line.endswith(text)), None)
    if code is None and kind == 'git-diff' and line.casefold() == ("error: Could not access '" + path + "'").casefold():
        code = checked['errno'] or None
    # stat checks visibility, not writability; a visible-but-not-writable target
    # is unexpected, not evidence of the specified ENOENT barrier.
    return {**base, 'errno': code, 'valid': code is not None and code == checked['errno'], 'diagnostic': line}


def probe_result(result, path):
    base = {'rc': result['returncode'], 'signal': result['signal'], 'path': path,
            'errno': None, 'identity': None, 'valid': False}
    if result.get('error') or result['signal'] is not None or result['returncode'] != 0:
        return base
    try:
        events = [decode(line) for line in result['stderr'].splitlines()]
        if not events or events[-1] != {'step': 'complete', 'rc': 0, 'errno': 0}:
            return base
        if any(not isinstance(e, dict) or type(e.get('rc')) is not int or type(e.get('errno')) is not int for e in events):
            return base
        opened = events[0]
        if opened['step'] != 'open':
            return base
        failed = next((e for e in events if e['rc'] < 0), None)
        identities = [e for e in events if e['step'] == 'identity']
        obj = {k: identities[0][k] for k in ('dev', 'ino', 'size')} if len(identities) == 1 else None
        if opened['rc'] >= 0 and obj is None:
            return base
        # A failure after open is not an opening-path barrier.
        return {**base, 'identity': obj, 'errno': failed['errno'] if failed else 0,
                'valid': failed is None or (failed is opened and failed['errno'] > 0)}
    except (ValueError, KeyError, TypeError):
        return base
