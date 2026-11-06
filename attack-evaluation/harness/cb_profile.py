"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
from net import UPSTREAM_HOST, QUESTION_HOST
HOSTS = {'api-key':'nb-decoy-cb-x.test','bearer':'nb-decoy-cb-t.test',
         'token':'nb-decoy-cb-t.test','basic':'nb-decoy-cb-k.test',
         'sink':'nb-decoy-cb-sink.test','http':'nb-decoy-cb-http.test'}
NAMES = tuple(dict.fromkeys((UPSTREAM_HOST,QUESTION_HOST,*HOSTS.values())))
ENDPOINTS = tuple((host,443) for host in NAMES if host != HOSTS['http']) + ((HOSTS['http'],80),)
# CB-14 条款 8 的保持连接上游：旁路端口 8443，一个已有 host。它是合法的账户/条目目的地，但 **不进 ENDPOINTS**——
# ENDPOINTS 是全局闭窗集（cb_upstream.end / cb_judge.window_requests），CB-01–12 每个窗口都要闭完它；keep 端点不参与闭窗。
KEEP_PORT = 8443
KEEP_ENDPOINTS = ((HOSTS['api-key'],KEEP_PORT),)
ROOT = '/nb-decoy-cb/'
