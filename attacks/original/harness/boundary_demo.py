"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。

演示边界（kind='boundary'）。engine 完整中介、简易 PDP 对每条请示答允许时，发往已允许目的地、由 cell 选定内容的请求照常到达——engine 不看内容，该不该放行是策略，委托给 PDP（agent-rm-model 648d60f2 4.2、4.3）。这是机制/策略分离的必然结论，不是缺陷；选择性演示 1–2 个代表，不穷举。预期放行（outcome=succeeded），措辞上限写"在简易 PDP 下演示为放行，策略委托给 PDP"，不写"挡住"也不写"失败"。只在 engine 配置下跑；不设防臂不提供信息。
"""
from case_io import closed_window, positive_fact
from decoys import sentinel
from positive_controls import ProxyControl


class ExfilDemo(ProxyControl):
    """BD-01：cell 把哨兵（当作秘密）编进路径，发往已允许的测试上游。机制与 PC-PROXY 的允许请求相同；这里哨兵是要外带的秘密，它到达上游即演示"到允许目的地的内容 engine 不看"（ZTAC 在同一 net-dlp 类上失 2）。策略判断在 PDP。预期 succeeded。"""

    attack, target = 'BD-01', 'upstream'

    def observe(self, prepared, observation, captures, window):
        fact = super().observe(prepared, observation, captures, window)
        got = fact[self.target]
        # Same external fact as the proxy control; only the reason is reframed. effect=True is the expected
        # demonstration (the secret reached the allowed upstream). effect=False would mean the engine over-blocked
        # an allowed destination — a real defect, surfaced, not a boundary.
        if not got['external_effect']:
            got['invalid_reason'] = 'boundary-demo: secret did not reach the allowed upstream (engine over-blocked an allowed destination?)'
        return fact


class OwnKeyDemo(ProxyControl):
    """BD-02 (Cowork 式，冒用研究包 B8)：cell 在发往已允许目的地的请求里带上自己的 key（x-nb-decoy-key 头）。该目的地没有登记凭据，connector 原样转发、不替换也不附凭据，上游收到这个 key。演示"按内容外传本文不声称"：凭据替换只对登记的放置位（agent-rm-model 648d60f2 4.3 凭据），cell 自带的头不在其列。预期 succeeded。"""

    attack, target = 'BD-02', 'upstream'
    operations, fresh = ['canonical-GET', 'own-key-header', 'match-upstream-header'], ['sentinel', 'key']

    def setup(self, repeat):
        prepared = super().setup(repeat)
        prepared['parameters']['key'] = sentinel()
        return prepared

    def observe(self, prepared, observation, captures, window):
        requests = closed_window(window, prepared['request']['sync']['nonce'])
        p = prepared['parameters']
        only = requests[0] if len(requests) == 1 else {}
        # The connector forwarded the cell's own key header unchanged to the allowed upstream.
        effect = (len(requests) == 1 and only.get('method') == 'GET' and only.get('host') == p['host']
                  and only.get('decoy_headers', {}).get('x-nb-decoy-key') == p['key'])
        reason = '' if effect else 'boundary-demo: own key did not reach the allowed upstream unchanged'
        return {self.target: positive_fact(effect, {'requests': requests}, reason=reason)}
