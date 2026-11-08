"""离线报告视图：区分批次质量、配置预期和正式身份，链接已有证据而不改判据。"""
import re

from common import LABELS, markdown, json_bytes

REPORT_VERSION = 2
STATES = {'completed': '完整结束', 'failed': '未完整结束', 'unknown': '无法确认'}


def expectation(row):
    """Compare recorded expectations, never silently repair historical evidence."""
    expected = row.get('expected', {})
    problems = []
    if expected.get('outcome') not in LABELS:
        return '未记录预期判决'
    if expected['outcome'] != row['outcome']:
        problems.append('判决不符')
    if row.get('mismatch'):
        problems.append('机制不符')
    if expected.get('mechanism') and expected['mechanism'] != row.get('observed_mechanism'):
        problems.append('预期机制未观察到')
    return '；'.join(problems) or '符合记录的预期'


def batch_status(header, rows):
    """Quality is independent of expected attack outcome and formal registration.

    COMPLETE.json proves archive completeness, not successful orderly shutdown.
    Missing old controller status is unknown, never upgraded to passed.
    """
    failures, unknown = [], []
    if 'controller_error' not in header:
        unknown.append('未记录主控结束状态')
    elif header['controller_error'] is not None:
        failures.append('主控错误：' + json_bytes(header['controller_error']).decode('utf-8').strip())
    if header.get('evidence_error'):
        failures.append('留证错误：' + json_bytes(header['evidence_error']).decode('utf-8').strip())
    cleanup = header.get('cleanup', {}).get('ok')
    if cleanup is not True:
        failures.append('清理未通过或未确认')
    if not rows:
        failures.append('无结果行')
    for row in rows:
        name = row['attack'] + '/' + row['config']
        attempts = row['attempts']
        if len(attempts) != row['repeats']:
            failures.append(name + '：计划重复未完成')
        if row['outcome'] == 'invalid' or any(
                a.get('fatal_error') or a['outcome'] == 'invalid' or any(
                    t['outcome'] == 'invalid' or t.get('quality_issue') for t in a['targets'])
                for a in attempts):
            failures.append(name + '：有无效观察/质量错误')
        if (row['config'] == 'engine' and row.get('kind', 'attack') == 'attack'
                and not row.get('pairing_finalized')):
            unknown.append(name + '：未记录跨配置配对完成')
    return {'state': 'failed' if failures else 'unknown' if unknown else 'completed',
            'reasons': failures + unknown}


def status_lines(header, rows):
    status = batch_status(header, rows)
    formal = '正式身份已核对（不等于批次通过）' if header.get('formal') else '试跑，不算数'
    lines = [f"**批次状态：{STATES[status['state']]}；{formal}。**", '',
             'COMPLETE.json 只表示归档完整；逐项观测不等于整批通过。', '']
    lines += ['- ' + markdown(reason) for reason in status['reasons']]
    if status['reasons']:
        lines.append('')
    return lines


def evidence_links(value):
    """Only manifest-style flat evidence names can become local Markdown links."""
    names = set()

    def visit(item):
        if isinstance(item, dict):
            name = item.get('file')
            if (isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}', name)
                    and all(key in item for key in ('blob', 'sha256', 'bytes'))):
                names.add(name)
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
    visit(value)
    return ', '.join(f'[{name}]({name})' for name in sorted(names)) or '—（未记录引用）'


def yes(value):
    return '是' if value is True else '否' if value is False else '未记录'


def detail_lines(row):
    expected = row.get('expected', {})
    lines = [f"## {markdown(row['attack'])} / {markdown(row['config'])}", '',
             '预期机制：' + markdown(expected.get('mechanism') or '不要求防护机制') +
             '；预期位置（规格/源码，不是动态定位）：' + markdown(expected.get('location') or '不适用') +
             '；实际观察机制：' + markdown(row.get('observed_mechanism') or '未观察到防护机制') + '。', '',
             '| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |',
             '|---|---|---|---|---|---|---|---|---|---|---|']
    for attempt in row['attempts']:
        for target in attempt['targets']:
            pairing = target.get('pairing', {})
            prerequisite = (yes(pairing.get('satisfied')) if pairing else
                            yes(target.get('prerequisite_ok')) if row['config'] == 'undefended' else '不适用')
            values = [attempt['repeat'], target['id'], LABELS[target['outcome']],
                      yes(target.get('control', {}).get('ok')), yes(target.get('target_verified')),
                      yes(target.get('complete')), yes(target.get('external_effect')), prerequisite,
                      target.get('observed_mechanism') or '—',
                      target.get('invalid_reason') or target.get('quality_issue') or '—']
            lines.append('| ' + ' | '.join(map(markdown, values)) + ' | ' +
                         evidence_links([attempt.get('evidence'), target.get('external_fact')]) + ' |')
    lines += ['', '脚本 sha256：' + markdown(row['script'].get('sha256', '未记录')) +
              '；请求契约：' + markdown(row['request_contract']) + '。', '']
    return lines
