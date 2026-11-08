"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from collections import deque
import importlib
import os
import struct
import sys
import unittest
from unittest.mock import Mock, patch

from deploy_fixtures import ENGINE_SOURCE


@unittest.skipUnless(os.name == "posix", "production canonical uses Linux fcntl; no sockets/listeners used")
class ProductionWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ENGINE_SOURCE))
        try:
            cls.admin = importlib.import_module("client.admin")
            cls.link = importlib.import_module("client.link")  # v4: Link lives in client/link.py
            cls.render = importlib.import_module("client.render")
            cls.attach = importlib.import_module("client.attach")
            cls.c = importlib.import_module("connector.canonical")
        finally:
            sys.path.pop(0)

    def fields(self, qid=7):
        c = self.c
        # 24 fields since v4: field 18 is the matched cell (state, methods, prefixes, accounts, approval, named
        # addresses), here the harness's ask-every-time cell on the question host (management.question_entry);
        # then six host-file fields, empty for a network request (op 0, alias, path, start, length, object).
        cell = c.pack_list([c.u8(1), c.pack_list([b"POST"]), c.pack_list([b"/"]), c.pack_list([]), c.u8(2),
                            c.pack_list([])])
        return [c.u64(qid), b"abcdef:1", b"work2", c.u8(1), b"nb-decoy-question.test:443", b"POST", b"https",
                b"nb-decoy-question.test", c.u16(443), b"/nb-request", b"", c.pack_list([]), c.pack_list([]),
                b"application/octet-stream", c.pack_list([]), c.u64(4), c.pack_list([]), cell,
                c.u8(0), b"", b"", c.u64(0), c.u64(0), c.pack_list([])]

    def test_fragmented_question_scm_rights_body_and_one_shot_answer(self):
        c = self.c
        fd = c.seal_body(b"body")
        initial_offset = os.lseek(fd, 0, os.SEEK_CUR)
        wire = c.pack_frame(c.QUESTION, self.fields())
        link = self.link.Link.__new__(self.link.Link)
        link.sock, link.fds = Mock(), deque()
        link.parser = c.FrameParser(c.LIMITS.frame_bd, c.LINK_D_TO_CLIENT)
        session = self.admin.Session()
        try:
            with patch.object(self.link.socket, "recv_fds", side_effect=[(wire[:5], [fd], 0, None),
                                                                         (wire[5:], [], 0, None)]):
                self.assertEqual(link.receive(), [])
                frames = link.receive()
            self.assertEqual(frames[0][2], fd)
            session.on_frame(*frames[0])
            self.assertEqual(session.current.body(None), b"body")
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), initial_offset)  # positional read did not disturb shared fd
            _, answer = session.on_line("allow-once")
            parser = c.FrameParser(c.LIMITS.frame_bd, c.LINK_D_TO_CORE)
            kind, fields = parser.feed(answer)[0]
            self.assertEqual(kind, c.ANSWER)
            self.assertEqual(c.read_uint(fields[0], 8), 7)
            self.assertEqual(c.read_uint(fields[1], 1), 1)
            session.on_frame(c.OK, [c.u8(c.ANSWER), c.pack_list([])], None)
            with self.assertRaises(OSError):
                os.fstat(fd)
        finally:
            session.close()
            link.close()

    def test_eof_closes_pending_fd_and_session_close_closes_unanswered_fd(self):
        c = self.c
        for transfer in (False, True):
            fd = c.seal_body(b"body")
            link = self.link.Link.__new__(self.link.Link)
            link.sock, link.fds = Mock(), deque([fd] if not transfer else [])
            session = self.admin.Session()
            if transfer:
                session.on_frame(c.QUESTION, self.fields(), fd)
            session.close()
            link.close()
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_attachment_uses_distinct_framing_and_clipboard_filter(self):
        wire = self.attach.frame(self.attach.INPUT, b"start\n")
        self.assertEqual(wire, b"\x01" + struct.pack(">I", 6) + b"start\n")
        screen = self.attach.ClipboardFilter()
        result = screen.feed(b"hello\x1b]52;c;secret") + screen.feed(b"\x07world")
        self.assertEqual(result, b"helloworld")

    def test_admin_renderer_escapes_newline_prompt_forgery(self):
        fields = self.fields()
        fields[9] = b"/x\nanswer question 999 [allow-once]: "
        q = self.render.Question.parse(fields, None)
        text = "\n".join(self.render.question_lines(q))
        self.assertNotIn("\nanswer question 999", text)
        self.assertIn(r"\x0aanswer question 999", text)
