# 20261105T173424Z-v4-s2-selfcheck-core

这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

**试跑，不算数。**


- engine：ExperimentLab/engine-v3 @ a9eff99970997f34d2babdb03f2857b6122e3e4b；登记基线 None；formal=False（deliberately wrong engine (selfcheck-core): never formal; compiled source differs from the registered v4 export, file by file）
- 配置：engine, undefended；变体：selfcheck-core
- 起止（UTC）：2026-11-05T17:34:24.138379+00:00 — 2026-11-05T17:35:41.549742+00:00
- kernel：6.6.87.2-microsoft-standard-WSL2
- policy：sha256:2f8e38a375eb20a628497df14f1b75316f6bc4a1d6e25190d2b7ea2046bb2e4b；部署：{'seed': {'python': 'Python 3.12.3', 'libraries': ['lib/x86_64-linux-gnu/libbz2.so.1.0', 'lib/x86_64-linux-gnu/libc.so.6', 'lib/x86_64-linux-gnu/libcrypt.so.1', 'lib/x86_64-linux-gnu/libcrypto.so.3', 'lib/x86_64-linux-gnu/libdb-5.3.so', 'lib/x86_64-linux-gnu/libexpat.so.1', 'lib/x86_64-linux-gnu/libffi.so.8', 'lib/x86_64-linux-gnu/libgdbm.so.6', 'lib/x86_64-linux-gnu/liblzma.so.5', 'lib/x86_64-linux-gnu/libm.so.6', 'lib/x86_64-linux-gnu/libncursesw.so.6', 'lib/x86_64-linux-gnu/libpanelw.so.6', 'lib/x86_64-linux-gnu/libreadline.so.8', 'lib/x86_64-linux-gnu/libsqlite3.so.0', 'lib/x86_64-linux-gnu/libssl.so.3', 'lib/x86_64-linux-gnu/libtinfo.so.6', 'lib/x86_64-linux-gnu/libz.so.1', 'lib64/ld-linux-x86-64.so.2'], 'not_found': [], 'scripts': {'DF-01.py': '874fd80123135a036bd61b5aca61b45e88312342', 'DF-03.py': 'ef86af1a3d93bf309ceed3795a036bef8d347f71', 'DF-05.py': '2aaef0552a17ec1a3d3dcaa2c23871054bb94f43', 'DF-06.py': 'a247c586342a54e506ee7853c09b2090c9f54d04', 'DF-07.py': '3680aab2e95cb203ec93cb6280452811bf1df680', 'DF-08.py': 'ebd723155e612b17bdf5831daa6b59708d196d86', 'DF-09.py': '6c4caf3160dc1f9370fc79318cf5f40a8aeaa49e', 'DF-10.py': '866ebf1b3ad6e6210cdcae21c327c21a998d5eec', 'DF-12.py': 'db02272543452146a166488a20e0ad780bd26cc3', 'DF-16.py': '22e70fe2cdaf8e0690f6ceb7307e0b1d7b7ab64d', 'DF-17.py': '0d76de76da5a45f83190b96daeb42fb6c43ac775', 'DF-18.py': '6a4b24174e18c09af8f8e97d00baca5876d17b11', 'DF-19.py': '92005f6ba3a67946d9b0e18e37ce0ec29fb3baf8', 'PC-ALLOW.py': '83df41e51295ab822cec1a458eccfd1cbe0bd09f', 'PC-CELL.py': '09f08fc3a06dad292071bed681c48b35dd25919f', 'PC-CRED.py': '3b3279c412d954ec560bda63972e8b266dadeed4', 'PC-FALLBACK.py': 'cfa24e92d14abf6142389709dfa1f5d56d0c7eba', 'PC-ONCE.py': '8ee680721ed9ea7be065b903430e831aa438e84a', 'PC-RECHECK.py': '0906aff544b8ef2ea802a50a6537f77dd00e331c', 'PC-STREAM.py': '132fa55942a8959788eed4fccfa23abf606d95d0', 'df_runner.py': '044bb4613bbcbe75f6aa6c55381a102d5920b18a', 'df_wire.py': '8ab0b179fbd6363740c07d23acad4a9830012f83'}}, 'policy_digest': 'sha256:2f8e38a375eb20a628497df14f1b75316f6bc4a1d6e25190d2b7ea2046bb2e4b', 'catalog_digest': 'sha256:9dda28399166eb2e7b47dc0f239a84b4eda8308c9d1c5278b716fe8a224e12f6', 'components_digest': 'sha256:141d744180385de15411f9572ca2b91308716cb78232e2aefe5b6ea76abd0df0', 'uid_range': {'first': 70000, 'last': 70010}, 'capacity': 11, 'connector_argv': ['/usr/bin/python3', '-I', '-B', '/tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/harness/df_connector_log.py', '/tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/nb-decoy-connector-logs', '/tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/src/ExperimentLab/engine-v3/bin/connector', '--library', '/var/lib/nb-decoy-df-v4-s2-selfcheck-core/libw2sandbox.so', '--ca-file', '/tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/nb-decoy-ca.pem']}
- 清理：ok=True；失败 0 项
- 主控错误：无；留证错误：无
- trace 判定：True（检查 18 条）
- 完成条件：{"subgoals": 9, "subgoals_with_valid_pair": 9, "positive_controls_passed": false, "trace_ok": true, "offline_selfcheck_passed": false}

## harness 与脚本

- df_admin.py: blob 4fa196bc98bdb58e91b9c14b148e8f6cf4d92b35
- df_baseline.py: blob 2c2299105c03d888c6e0761ddcf8df6c7badb965
- df_batch.py: blob 935a5f0d90eff26b628795cf9fb373ed46bd7595
- df_cleanup.py: blob 3cd585dafabcb999bb88cf7f54ebc17e60a8fa97
- df_common.py: blob 36622803664d89c14c431eaabe3c1bb16338a8e7
- df_connector_log.py: blob b4d63b449b044b52873ada252d2d5bcf81eea7f6
- df_control.py: blob 1959e6994b335c62a75e6bf129c1d901c0dc8bf8
- df_deploy.py: blob d7bf395b79739f5c62842470fac43b48e1ce0262
- df_drivers.py: blob 1ef601d7b9503d6dfb1bcb8fe39d728a0f482d55
- df_env.py: blob 501d9722c7e1f39fb1e8bd3ae69086bbba6f0ffd
- df_judge.py: blob b384e9944f4c25844288ecc977c14a8b42326c59
- df_judges.py: blob abaec3ce7441ac45aaede66cf23bb71ed0e86eb0
- df_net.py: blob 0ec997caa14c66498fa6dcb4c3928605686e5e73
- df_pdp_hold.py: blob 60e56f097092608c0e8540196d5e996104801131
- df_proc.py: blob 743bde5098db3d2ea00b3cbdb53d9f1fae2537e5
- df_record.py: blob 1122c12d5614c12c1e4ceace2b08b939b811d5b5
- df_registry.py: blob 9cce2cc79a12e973e1e95cfd68db95fd3cef8b0f
- df_safeio.py: blob 00ce6867d8ce149a5436781dca5a5b359fba75e1
- df_testnet.py: blob eb08c330a15bdf561d87f2677fee218f5198aa67
- df_tls.py: blob 1dd106250d4030886ce455fb3513dc84bfa297fb
- df_variants.py: blob 3d39548bdfda5e87a8dd3aaea84a6a78400032c4

## 命令

- `-C /mnt/d/Thesis archive --format=tar a9eff99970997f34d2babdb03f2857b6122e3e4b ExperimentLab/engine-v3` → 0
- `/usr/bin/make -s -C /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/src/ExperimentLab/engine-v3/native sandbox BUILD_DIR=/tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/build` → 0
- `build -trimpath -buildvcs=false -o /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/build/engine-frontend .` → 0
- `-trimpath -buildvcs=false -ldflags=-s -w -o /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/build/engine-mcp .` → 0
- `/usr/sbin/mkfs.btrfs -q /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/runtime.btrfs` → 0
- `/usr/sbin/mkfs.btrfs -q /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/workspace.btrfs` → 0
- `/usr/bin/mount -o loop,nosuid,nodev /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/runtime.btrfs /var/lib/nb-decoy-df-v4-s2-selfcheck-core` → 0
- `/usr/bin/mount -o loop,nosuid,nodev /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/workspace.btrfs /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/workspaces` → 0
- `/usr/sbin/ip -j link show` → 0
- `/usr/sbin/ip link set lo up` → 0
- `/usr/bin/unshare --net /usr/bin/sleep 568` → started
- `veth peer name nb-decoy-r4c0e netns 1984` → 0
- `/usr/sbin/ip address add 93.184.216.1/30 dev nb-decoy-r4c0e` → 0
- `/usr/sbin/ip link set nb-decoy-r4c0e up` → 0
- `-- /usr/sbin/ip link set lo up` → 0
- `/usr/sbin/ip address add 93.184.216.2/30 dev nb-decoy-t4c0e` → 0
- `/usr/sbin/ip address add 10.66.0.10/32 dev lo` → 0
- `add 10.66.0.10/32 via 93.184.216.2 dev nb-decoy-r4c0e` → 0
- `/usr/sbin/ip address add 169.254.169.254/32 dev lo` → 0
- `add 169.254.169.254/32 via 93.184.216.2 dev nb-decoy-r4c0e` → 0
- `-- /usr/sbin/ip link set nb-decoy-t4c0e up` → 0
- `/usr/sbin/ip -j route show table all` → 0
- `/usr/bin/mount --bind /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/net/nb-decoy-hosts /etc/hosts` → 0
- `/usr/bin/mount --bind /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/net/nb-decoy-resolv.conf /mnt/wsl/resolv.conf` → 0
- `-- /usr/bin/python3 -I -B /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/harness/df_testnet.py /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/net/nb-decoy-testnet-test.json` → started
- `/usr/bin/python3 -I -B /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/harness/df_testnet.py /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/net/nb-decoy-testnet-run.json` → started
- `/usr/bin/python3 -I -B /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/src/ExperimentLab/engine-v3/frontend/make_ca_pool.py /var/lib/nb-decoy-df-v4-s2-selfcheck-core/ca-pool 11` → 0
- `/usr/bin/btrfs filesystem show --raw /var/lib/nb-decoy-df-v4-s2-selfcheck-core` → 0
- `/usr/bin/btrfs subvolume create /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/workspaces/work0` → 0
- `/usr/bin/mount --bind /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/workspaces/work0 /var/lib/nb-decoy-df-v4-s2-selfcheck-core/work0` → 0
- `/usr/bin/btrfs subvolume create /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/workspaces/work1` → 0
- `/usr/bin/mount --bind /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/workspaces/work1 /var/lib/nb-decoy-df-v4-s2-selfcheck-core/work1` → 0
- `/tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/build/w2-catalog /var/lib/nb-decoy-df-v4-s2-selfcheck-core catalog.json` → 0
- `/tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/src/ExperimentLab/engine-v3/bin/engine /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/build/libw2sandbox.so /var/lib/nb-decoy-df-v4-s2-selfcheck-core catalog.json /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/nb-decoy-evidence/events.jsonl --measure-completion` → started
- `--no-new-privs /usr/bin/python3 -I -B /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/src/ExperimentLab/engine-v3/bin/simple-pdp /var/lib/nb-decoy-df-v4-s2-selfcheck-core/hook/pdp.sock` → started
- `--ambient-caps=-all --no-new-privs /usr/bin/python3 -I -B /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/scripts/df_runner.py` → started
- `--ambient-caps=-all --no-new-privs /usr/bin/python3 -I -B /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/scripts/df_runner.py` → started
- `--ambient-caps=-all --no-new-privs /usr/bin/python3 -I -B /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/scripts/df_runner.py` → started
- `--ambient-caps=-all --no-new-privs /usr/bin/python3 -I -B /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/scripts/df_runner.py` → started
- `--ambient-caps=-all --no-new-privs /usr/bin/python3 -I -B /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/scripts/df_runner.py` → started
- `/usr/bin/python3 -I -B /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/harness/df_pdp_hold.py /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/src/ExperimentLab/engine-v3 /var/lib/nb-decoy-df-v4-s2-selfcheck-core/hook/pdp.sock` → started
- `--ambient-caps=-all --no-new-privs /usr/bin/python3 -I -B /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/scripts/df_runner.py` → started
- `--ambient-caps=-all --no-new-privs /usr/bin/python3 -I -B /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/scripts/df_runner.py` → started
- `--no-new-privs /usr/bin/python3 -I -B /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/src/ExperimentLab/engine-v3/bin/simple-pdp /var/lib/nb-decoy-df-v4-s2-selfcheck-core/hook/pdp.sock` → started
- `--ambient-caps=-all --no-new-privs /usr/bin/python3 -I -B /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/scripts/df_runner.py` → started
- `/usr/bin/umount /var/lib/nb-decoy-df-v4-s2-selfcheck-core/work1` → 0
- `/usr/bin/umount /var/lib/nb-decoy-df-v4-s2-selfcheck-core/work0` → 0
- `/usr/bin/umount /mnt/wsl/resolv.conf` → 0
- `/usr/bin/umount /etc/hosts` → 0
- `/usr/bin/umount /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/workspaces` → 0
- `/usr/bin/umount /var/lib/nb-decoy-df-v4-s2-selfcheck-core` → 0
- `/usr/sbin/losetup --list --json --associated /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/runtime.btrfs` → 0
- `/usr/sbin/losetup --list --json --associated /tmp/nb-decoy-df-v4-s2-selfcheck-core-98641c3b/workspace.btrfs` → 0
