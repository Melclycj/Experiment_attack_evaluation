"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import ast
import copy
from dataclasses import dataclass
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from cb_variant import ANCHOR, transform, prepare_variant, HELPER
from build import inventory
from record import formal_status

SOURCE = Path(__file__).resolve().parents[6] / 'ExperimentLab/engine-v3'  # registered baseline v4


class VariantPreparation(unittest.TestCase):
    def test_current_source_transforms_without_importing_engine(self):
        data=(SOURCE/'connector/upstream.py').read_bytes()
        patched=transform(data)
        self.assertEqual(patched.count(b'link, resp = _nb_decoy_follow_once'),1)
        self.assertIn(b'zero_values(headers)',patched)
        self.assertIn(b'answer.zero()',patched)
        ast.parse(patched)
        self.assertFalse(formal_status({'variant':'redirect-credentials'}))

    def test_drift_and_second_patch_fail_closed(self):
        for data in (b'pass\n',(SOURCE/'connector/upstream.py').read_bytes().replace(ANCHOR.encode(),b''),
                     transform((SOURCE/'connector/upstream.py').read_bytes())):
            with self.assertRaises(ValueError):transform(data)

    def test_exclusive_snapshot_keeps_original_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);source=base/'source';(source/'connector').mkdir(parents=True)
            (source/'connector/upstream.py').write_bytes((SOURCE/'connector/upstream.py').read_bytes())
            before=inventory(source);parent=base/'nb-decoy-variant';parent.mkdir()
            receipt=prepare_variant(source,parent/'engine')
            self.assertEqual(inventory(source),before)
            self.assertEqual(receipt['original'],before)
            self.assertNotEqual(receipt['patched'],before)
            self.assertFalse(receipt['formal'])
            self.assertIn('+                link, resp',receipt['patch'])
            with self.assertRaises(FileExistsError):prepare_variant(source,parent/'engine')


@dataclass
class Request:
    method:bytes=b'GET'
    scheme:bytes=b'https'
    host:bytes=b'nb-decoy-cb-x.test'
    port:int=443
    path:bytes=b'/nb-decoy-cb/redirect/302/n'
    query:bytes|None=None
    is_ip:bool=False


class MockRedirectBehavior(unittest.TestCase):
    def setUp(self):
        # Execute only the isolated helper over fakes; no engine or socket startup.
        scope={'ALLOW':1,'Refused':ValueError,'request_target':lambda r:r.path.decode(),
               'host_header':lambda r:r.host}
        exec(compile(HELPER,'self-check-helper-only','exec'),scope)
        self.follow=scope['_nb_decoy_follow_once']
        self.exchange=Mock();self.exchange.policy.allowed.return_value=True
        self.link=object();self.response=Mock(status=302)
        self.response.getheader.return_value='https://nb-decoy-cb-sink.test/nb-decoy-cb/collect/n'
        self.answer=SimpleNamespace(kind=1,account=b'nb-decoy-a',named=())  # v4 Answer.named (K-59)
        self.headers=[(b'x-api-key',bytearray(b'nb-decoy-test-secret'))]

    def test_one_local_https_hop_preserves_header_before_zeroing(self):
        link,resp=self.follow(self.exchange,Request(),self.answer,self.headers,self.link,self.response)
        self.exchange._connect.assert_called_once()
        target=self.exchange._connect.call_args.args[0]
        self.assertEqual(target.host,b'nb-decoy-cb-sink.test')
        # v4 Exchange._connect(req, named, account): the ALLOW's named list, never a resolved address list
        self.assertIs(self.exchange._connect.call_args.args[1],self.answer.named)
        self.assertEqual(self.exchange._connect.call_args.args[2],self.answer.account)
        link.conn.putheader.assert_any_call(b'x-api-key',self.headers[0][1])
        self.assertIs(resp,link.conn.getresponse.return_value)
        self.assertEqual(self.headers[0][1],b'nb-decoy-test-secret')

    def test_no_redirect_is_unchanged(self):
        self.response.status=200
        self.assertEqual(self.follow(self.exchange,Request(),self.answer,self.headers,self.link,self.response),
                         (self.link,self.response))
        self.exchange._connect.assert_not_called()

    def test_nondecoy_plaintext_credentials_in_url_and_second_hop_denied(self):
        for location in ('http://nb-decoy-cb-sink.test/nb-decoy-cb/collect/n',
                         'https://example.com/nb-decoy-cb/collect/n',
                         'https://user@nb-decoy-cb-sink.test/nb-decoy-cb/collect/n',
                         'https://nb-decoy-cb-sink.test:444/nb-decoy-cb/collect/n',
                         'https://nb-decoy-cb-sink.test/nb-decoy-cb/collect/n?x=y'):
            self.response.getheader.return_value=location
            with self.subTest(location=location),self.assertRaises(ValueError):
                self.follow(self.exchange,Request(),self.answer,self.headers,self.link,self.response)
        self.exchange._connect.assert_not_called()

    def test_failed_second_connection_is_dropped(self):
        self.exchange._connect.return_value.conn.endheaders.side_effect=OSError('test')
        with self.assertRaises(OSError):
            self.follow(self.exchange,Request(),self.answer,self.headers,self.link,self.response)
        self.exchange._drop.assert_any_call(self.exchange._connect.return_value)


if __name__=='__main__':unittest.main()
