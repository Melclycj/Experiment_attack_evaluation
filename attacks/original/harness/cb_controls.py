"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
from cb_accounts import Accounts
from cb_profile import HOSTS
from positive_controls import WorkspaceControl,ProxyControl,DialogueControl

class MeasuredControl:
    def prepare(self,config,repeat,contract):
        prepared=super().prepare(config,repeat,contract)
        self.credentials=Accounts(self.rt.deployment)
        values=self.credentials.create(HOSTS['api-key'],443,'api-key')
        self.rt.own(values.values(),self.attack,config)
        for value in values.values():self.credentials.register(value)
        prepared['all_accounts']=list(values.values())
        # Registration receipts (form digests, read-back truth-file identities) go into the
        # control's archived fact, as an attack's do, so its scans can be re-checked offline.
        prepared['metadata']=list(self.credentials.receipts)
        return prepared

    def restore(self,prepared):
        try:super().restore(prepared)
        finally:self.credentials.close()

class MeasuredFile(MeasuredControl,WorkspaceControl):pass
class MeasuredProxy(MeasuredControl,ProxyControl):pass
class MeasuredDialogue(MeasuredControl,DialogueControl):
    def interact(self,handle,prepared):
        # cb_row already holds the row's one attach client for the terminal capture
        # (relay: one client at a time); the dialogue runs on it and cb_row reads it to EOF.
        self.stream=handle.interaction
        self.exchange(self.stream,prepared)
