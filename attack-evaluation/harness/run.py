"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
from pathlib import Path
import sys
import time

HERE = Path(__file__).absolute().parent
sys.path[:0] = [str(HERE), str(HERE / 'cell')]
from common import MAX_OUTPUT, utc
from cb_output import directory_class
from run_batch import Batch
from run_boot import OUTER_RESERVE, discard, failure_marker, load_bundle, run_frozen, stage
from run_config import options, selection
from run_evidence import Evidence
from run_limits import alarm
from run_gate import release as release_gate
from run_registry import CASES, SUPPORT, SUPPORT_MODULES
from run_runtime import Runtime
from run_units import cases_for


def inside_main(host, arguments, absolute_deadline):
    if len(arguments) != 1:
        raise ValueError('one frozen context required')
    bundle = load_bundle(Path(arguments[0]))
    if bundle['deadline'] != absolute_deadline or bundle['cap'] != host['capacity']:
        raise ValueError('bootstrap context/deadline disagreement')
    cases = selection(bundle['attacks'], bundle['configs'], cases_for(bundle.get('unit', 'no-bypass'), CASES, bundle.get('targets',())))
    # Open the exclusively outer-created output without creating/reusing a run.
    directory = object.__new__(directory_class(bundle.get('unit', 'no-bypass')))
    directory.path, directory.limit, directory.finalized = Path(bundle['output']), MAX_OUTPUT - OUTER_RESERVE, False
    if directory.size() != 0:
        raise ValueError('output directory not empty at controller start')
    evidence = Evidence(directory)
    runtime_type,batch_type=Runtime,Batch
    if bundle.get('unit')=='credential-binding':
        from cb_runtime import CredentialRuntime
        from cb_batch import CredentialBatch
        runtime_type,batch_type=CredentialRuntime,CredentialBatch
    rt = runtime_type(bundle, host, absolute_deadline, evidence, support=SUPPORT)
    header = {'run': bundle['run'], 'engine': bundle['engine_identity'],
              'harness': bundle['harness_identity'], 'spec': bundle['spec_identity'],
              'configs': {cfg: bundle['engine_identity'] if cfg == 'engine' else
                          {'host_user': host['host_user'], 'kernel': host['kernel']} for cfg in bundle['configs']},
              'host': host, 'policy': {}, 'deployment': {}, 'commands': [],
              'started_at': bundle['started_at'], 'finished_at': utc(), 'cleanup': {'ok': False}}
    if bundle.get('unit'):
        header['unit'] = bundle['unit']
    if bundle.get('variant'):
        header['variant'] = bundle['variant']
        header['variant_provenance'] = evidence.raw(bundle['variant_provenance']['patch'].encode(),'variant.patch')
    return batch_type(rt, cases, bundle['configs'], header).execute()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['--frozen']:
        if len(argv) != 2:
            raise ValueError('invalid internal frozen invocation')
        bundle = load_bundle(Path(argv[1]))
        if HERE != Path(bundle['root']) / 'harness':
            raise ValueError('must execute the snapshotted entrypoint')
        from launch import run_controller
        try:
            result = run_controller(HERE / 'run.py', [argv[1]], bundle['cap'], Path(bundle['crash_directory']),
                                    absolute_deadline=bundle['deadline'])
            if result['forced'] or not (Path(bundle['output']) / 'COMPLETE.json').exists():
                failure_marker(bundle, 'forced/incomplete controller; cleanup unverified')
            return result['exit_code'] if result['exit_code'] and result['exit_code'] > 0 else int(
                result['forced'] or result['exit_code'] != 0)
        except BaseException as exc:
            if not (Path(bundle['output']) / 'LAUNCHER-FAILED.json').exists():
                failure_marker(bundle, type(exc).__name__ + ': ' + str(exc))
            raise
        finally:
            try:
                with alarm(bundle['deadline']):
                    discard(bundle)
                    release_gate(bundle)
            except BaseException as exc:
                if not (Path(bundle['output']) / 'LAUNCHER-FAILED.json').exists():
                    failure_marker(bundle, 'snapshot cleanup: ' + str(exc))
                raise
    args, cases = options(argv, CASES)
    if args.start != '开始':
        raise ValueError('no real batch authorized: explicitly say 开始 before --start 开始')
    if SUPPORT is None:
        raise ValueError('step-4 support modules not implemented; refusing fixture substitution')
    end, bundle, error = time.monotonic() + 600, None, None
    try:
        with alarm(end - 60):
            bundle = stage(args, cases, {} if args.unit=='credential-binding' else SUPPORT_MODULES, end)
        code = run_frozen(bundle)
        if not (Path(bundle['output']) / 'COMPLETE.json').exists():
            raise RuntimeError('controller did not finalize results (cleanup unverified)')
        return code
    except BaseException as exc:
        error = exc
        if bundle and not (Path(bundle['output']) / 'LAUNCHER-FAILED.json').exists():
            failure_marker(bundle, type(exc).__name__ + ': ' + str(exc))
        raise
    finally:
        if bundle:
            try:
                with alarm(end):
                    discard(bundle)
            except BaseException as exc:
                if not (Path(bundle['output']) / 'LAUNCHER-FAILED.json').exists():
                    failure_marker(bundle, 'snapshot cleanup: ' + str(exc))
                if error is None:
                    raise


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, TimeoutError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
