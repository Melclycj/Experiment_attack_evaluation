"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import json
from pathlib import Path
from cb_measure import environment
from common import json_bytes
from process_identity import ProcessRef, process_info
from run_transport import publish
from cell.nb_io import PublicationPending


def namespace_ids(status):
    fields=dict(line.split(':',1) for line in status.splitlines() if ':' in line)
    ids=[int(v) for v in fields.get('NSpid','').split()]
    if not ids or any(n<1 for n in ids):raise ValueError('NSpid mapping missing')
    return ids,int(fields['PPid'])


def find_process(group, ready, uid, *, parent=None):
    """Enumerate only this attempt's cgroup; never a host-wide process search."""
    if (set(ready)!={'pid','ppid','marker'} or type(ready['pid']) is not int or ready['pid']<1
            or type(ready['ppid']) is not int or ready['ppid']<0):
        raise ValueError('process handshake schema')
    found=[]
    for name in (group.path/'cgroup.procs').read_text().split():
        pid=int(name)
        try:
            info=process_info(pid);ns,ppid=namespace_ids(Path('/proc',name,'status').read_text())
        except FileNotFoundError:continue
        if info['uids']!=[uid]*4 or ns[-1]!=ready['pid']:continue
        if parent is not None and ppid!=parent:raise ValueError('declared child is not the pinned runner child')
        ref=ProcessRef(pid,uid,group)
        try:
            after=ref.read()
            if info['start_time']!=after['start_time']:raise ValueError('process changed during namespace mapping')
            found.append((ref,{'namespace_pids':ns,'host_ppid':ppid}))
        except BaseException:ref.close();raise
    if len(found)!=1:
        for ref,_ in found:ref.close()
        raise ValueError('no unique live process for declared namespace PID')
    return found[0]


class ProcessMeasurement:
    def __init__(self, rt, files, prepared):
        self.rt,self.files,self.prepared=rt,files,prepared
        self.handle=None;self.items=[];self.done=False

    def pump(self):
        if self.done or self.handle is None:return
        p=self.prepared['parameters'];measure=p['measurement'];h=self.handle
        group=h.group if h.config=='undefended' else self.rt.cgroup
        uid=1000 if h.config=='undefended' else h.uid
        if uid is None:return
        if not self.items:
            try:ready=json.loads(self.files.files.read(measure['ready'],4096))
            except (FileNotFoundError,PublicationPending):return
            if ready.get('marker')!=measure['marker']:raise ValueError('parent handshake marker mismatch')
            ref,ns=find_process(group,ready,uid)
            try:
                receipt,raw=environment(ref)
                self.rt.command.budget.consume(raw)
                self.items.append({'ref':ref,'raw':raw,'receipt':{**receipt,**ns,'stage':'initial',
                    'role':'undefended-parent' if h.config=='undefended' else 'runner'}})
                publish(self.files.files,measure['release'],json_bytes(ready))
            except BaseException:
                if not self.items:ref.close()
                raise
        if p.get('worker_ready') and len(self.items)==1:
            try:ready=json.loads(self.files.files.read(p['worker_ready'],4096))
            except (FileNotFoundError,PublicationPending):return
            if ready.get('marker')!=p['marker']:raise ValueError('child handshake marker mismatch')
            parent=self.items[0]['ref'].read()
            ref,ns=find_process(group,ready,uid,parent=parent['pid'])
            try:
                receipt,raw=environment(ref);self.rt.command.budget.consume(raw)
                self.items.append({'ref':ref,'raw':raw,'receipt':{**receipt,**ns,'role':'declared-child','stage':'initial'}})
                # A second stable sample witnesses the same child prior to release.
                second,again=environment(ref)
                if again!=raw:raise ValueError('child environment changed during handshake')
                self.items[-1]['receipt']['second_sample']=second
            except BaseException:
                if len(self.items)==1:ref.close()
                raise

    def finish(self):
        expected=2 if self.prepared['parameters'].get('worker_ready') else 1
        self.done=True
        return len(self.items)==expected and all(x['ref'].exited() for x in self.items)

    def close(self):
        self.done=True
        for item in self.items:item['ref'].close()
