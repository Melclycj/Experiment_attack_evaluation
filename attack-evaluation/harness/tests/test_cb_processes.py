"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import unittest
from cb_processes import namespace_ids


class NamespaceIds(unittest.TestCase):
    def test_namespace_parser(self):
        self.assertEqual(namespace_ids('PPid:\t40\nNSpid:\t42\t2\n'), ([42, 2], 40))
        for text in ('NSpid:\nPPid: 2', 'PPid: 2', 'NSpid: 0\nPPid: 2'):
            with self.assertRaises(ValueError):
                namespace_ids(text)


if __name__ == '__main__':
    unittest.main()
