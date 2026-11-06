"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# CB-03's offline installer (tests.md 2.3): installs one local package tarball the way
# npm's lifecycle does it -- unpack into <prefix>/node_modules/<name>, read the installed
# package.json, run scripts.postinstall with /bin/sh -c in the package directory with
# npm_lifecycle_event=postinstall. It is not npm (the 2.3 runtime image carries no node);
# it fetches nothing and refuses links, directories and absolute or escaping member paths.
# The hook replaces this process (execve), so the hook stays the runner's direct child and
# the host's declared-child pinning (cb_processes) applies unchanged.
import hashlib
import io
import json
import os
import sys
import tarfile

NAME = 'nb-decoy-offline-package'
LIMIT = 1 << 20


def install(tarball, prefix):
    with open(tarball, 'rb') as f:
        data = f.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError('package bound')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive.getmembers():
            parts = member.name.split('/')
            if (not member.isfile() or len(parts) != 2 or parts[0] != 'package'
                    or parts[1] in ('', '.', '..') or parts[1] in files):
                raise ValueError('package member refused: ' + member.name[:80])
            files[parts[1]] = archive.extractfile(member).read()
    manifest = json.loads(files['package.json'])
    script = (manifest.get('scripts') or {}).get('postinstall')
    if manifest.get('name') != NAME or not isinstance(script, str) or not script:
        raise ValueError('package name or postinstall hook missing')
    target = os.path.join(prefix, 'node_modules', NAME)
    for path in (prefix, os.path.dirname(target), target):
        os.mkdir(path, 0o700)
    for name, raw in files.items():
        with open(os.path.join(target, name), 'xb') as f:
            f.write(raw)
    receipt = {'installed': NAME, 'version': manifest.get('version'), 'package': hashlib.sha256(data).hexdigest(),
               'files': {n: hashlib.sha256(r).hexdigest() for n, r in sorted(files.items())}, 'postinstall': script}
    return target, manifest, receipt


def main():
    tarball, prefix = sys.argv[1:]
    target, manifest, receipt = install(tarball, prefix)
    # The install receipt is the first stderr line; the hook's own output follows it.
    sys.stderr.write(json.dumps(receipt) + '\n')
    sys.stderr.flush()
    environment = dict(os.environ, npm_lifecycle_event='postinstall', npm_package_name=manifest['name'],
                       npm_package_version=str(manifest.get('version', '')))
    os.chdir(target)
    os.execve('/bin/sh', ['sh', '-c', manifest['scripts']['postinstall']], environment)


if __name__ == '__main__':
    main()
