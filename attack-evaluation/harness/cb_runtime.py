"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
from run_runtime import Runtime

class CredentialRuntime(Runtime):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.cb_accounts=[];self.row_accounts={};self.undefended_environment={}
        self.cb_attempts=[];self.cb_owners={};self.cb_e09_seen=b''

    def own(self,credentials,attack,config,branch=None):
        """Recorded at creation, before registration can fail, so a batch-exit hit is attributable."""
        for c in credentials:
            if c.account in self.cb_owners:raise ValueError('credential account reused across attempts')
            self.cb_owners[c.account]={'attack':attack,'config':config,'branch':branch}
            self.cb_accounts.append(c)

    def arm(self,config):
        if any(not r.closed for r in self.rows):raise ValueError('previous credential row is live')
        # CB creates real reference rows per target, not NB's persistent victims.
        self.use(config)  # v4: the arm's own work0 (deployment's for engine, host user's for undefended)
        self.active=config
