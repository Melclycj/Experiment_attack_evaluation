"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
PLACEMENTS=('api-key','bearer','token','basic')
HOSTS={'api-key':'nb-decoy-cb-x.test','bearer':'nb-decoy-cb-t.test',
       'token':'nb-decoy-cb-t.test','basic':'nb-decoy-cb-k.test',
       'sink':'nb-decoy-cb-sink.test','http':'nb-decoy-cb-http.test'}
# These are subtargets, not additional attack IDs or statistical repetitions.
BRANCHES={
 'CB-01':('api-key-mcp',),
 'CB-02':('api-key-gateway','api-key-device'),
 'CB-03':('api-key-github','api-key-npm','api-key-cloud'),
 'CB-04':('api-key-service',),'CB-05':('api-key-child',),
 'CB-06':tuple(p+'-'+b for p in PLACEMENTS for b in ('empty','own')),
 'CB-07':tuple(p+'-'+b for p in PLACEMENTS for b in ('body','query','other','dual')),
 'CB-08':tuple(p+'-sink' for p in PLACEMENTS),
 'CB-09':tuple(p+'-'+b for p in PLACEMENTS for b in ('unique','selected')),
 'CB-10':tuple(p+'-'+b for p in PLACEMENTS for b in ('302','307','308')),
 'CB-11':tuple(p+'-http' for p in PLACEMENTS),
 'CB-12':tuple(p+'-host' for p in PLACEMENTS),
 'CB-14':('api-key-reuse',),  # 条款 8: one keep-alive connection, an authed frame then a header-less frame
 'PC-CREDENTIAL':tuple(p+'-valid' for p in PLACEMENTS)}

def split(branch):
    for placement in PLACEMENTS:
        if branch.startswith(placement+'-'):return placement,branch[len(placement)+1:]
    raise ValueError('unregistered credential branch')

def mechanism(attack):
    if attack in ('CB-01','CB-02','CB-03','CB-04','CB-05'):return 'truth-outside-agent'
    return {'CB-06':'row-account-selection','CB-07':'registered-placement-only',
            'CB-08':'row-account-selection','CB-09':'row-account-selection',
            'CB-10':'no-redirect-follow','CB-11':'https-release-only',
            'CB-12':'canonical-host-rejection','CB-14':'connection-account-isolation',
            'PC-CREDENTIAL':'allowed'}[attack]
