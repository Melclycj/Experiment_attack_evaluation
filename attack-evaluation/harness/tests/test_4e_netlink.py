"""Pure NB-26 wire/parser and syscall sequencing tests; system calls are mocked."""
import copy
import errno
import struct
import unittest
from unittest.mock import Mock, patch
from nb_netlink import attr, attributes, dump, exchange, messages, veth, HDR, IFINFO
from nb_userns import perform, NEWUSER, NEWNET, Syscalls
from userns_report import validate, blocked, Replay
from foure_fixtures import req, report, message, listing


class WireTests(unittest.TestCase):
    def test_veth_peer_holder_pid_and_nested_fields(self):
        pkt=veth(42,'nbdl1','nbdp1',2)
        self.assertEqual(HDR.unpack_from(pkt),(len(pkt),16,0x605,2,0))
        attrs=attributes(pkt[HDR.size+IFINFO.size:])
        self.assertEqual(attrs[3],b'nbdl1\0')
        link=attributes(attrs[18]);self.assertEqual(link[1],b'veth\0')
        peer=attributes(attributes(link[2])[1][IFINFO.size:])
        self.assertEqual(peer[3],b'nbdp1\0');self.assertEqual(struct.unpack('=I',peer[19])[0],42)

    def test_only_bounded_owned_interface_names_and_pid(self):
        for args in ((1,'nbdl','nbdp'),(True,'nbdl','nbdp'),(42,'eth0','nbdp'),
                     (42,'nbdl','nbd'+'a'*13),(42,'nbd-a','nbdp')):
            with self.subTest(args=args),self.assertRaises(ValueError):veth(*args,2)

    def test_multipart_list_and_negative_kernel_ack_are_distinct_from_send(self):
        packet=dump(1);ctl=exchange(packet,listing=True,factory=lambda *_:Replay(listing()))
        self.assertEqual(ctl['links'],[{'ifindex':1,'ifname':'lo'}]);self.assertTrue(ctl['complete'])
        r=report(req());self.assertEqual(r['netlink']['send_errno'],0)
        self.assertEqual(r['netlink']['send_rc'],len(bytes.fromhex(r['netlink']['request_hex'])))
        self.assertEqual(r['netlink']['ack_errno'],-errno.EPERM)

    def test_bad_headers_attributes_sequence_and_dump_interrupt(self):
        for data in (b'a',HDR.pack(999,2,0,1,0),message(3,b'',2),message(3,b'',1,0x10)):
            with self.subTest(data=data),self.assertRaises(ValueError):messages(data,1)
        for data in (b'a',struct.pack('=HH',3,1),attr(1,b'a')+attr(1,b'b')):
            with self.subTest(data=data),self.assertRaises(ValueError):attributes(data)

    def test_short_send_nonkernel_oversize_and_unexpected_response(self):
        for mode in ('short','nonkernel','large','unknown','positive'):
            fake=Mock();fake.sendto.return_value=len(dump(1))
            fake.recvfrom.return_value=(message(3,b'',1),(0,0))
            if mode=='short':fake.sendto.return_value=1
            if mode=='nonkernel':fake.recvfrom.return_value=(message(3,b'',1),(10,0))
            if mode=='large':fake.recvfrom.return_value=(b'x'*32769,(0,0))
            if mode=='unknown':fake.recvfrom.return_value=(message(44,b'',1),(0,0))
            if mode=='positive':fake.recvfrom.return_value=(message(2,struct.pack('=i',1),1),(0,0))
            with self.subTest(mode=mode),self.assertRaises(ValueError):
                exchange(dump(1),listing=True,factory=lambda *_:fake)
            fake.close.assert_called_once()

    def test_io_failure_retained_not_complete(self):
        for where in ('sendto','recvfrom'):
            fake=Mock();fake.sendto.return_value=len(dump(1))
            getattr(fake,where).side_effect=OSError(errno.EPERM,'mock')
            value=exchange(dump(1),listing=True,factory=lambda *_:fake)
            self.assertFalse(value['complete']);self.assertIsNone(value['ack_errno'])
            self.assertEqual(value['send_errno'] if where=='sendto' else value['io_errno'],errno.EPERM)
            fake.close.assert_called_once()


class SequenceTests(unittest.TestCase):
    def run_sequence(self, user=0, mapping=0, net=0):
        ops=Mock();order=[]
        def unshare(flags):
            order.append(('unshare',flags));rc={0:0,NEWUSER:user,NEWNET:net}[flags]
            return {'rc':rc,'errno':0 if rc==0 else errno.EPERM}
        ops.unshare.side_effect=unshare
        ops.clone.side_effect=lambda modern:order.append(('clone',modern)) or {'rc':-1,'errno':errno.EPERM}
        ops.map_uid.side_effect=lambda uid:order.append(('map',uid)) or {'rc':mapping,'errno':0 if mapping==0 else errno.EPERM}
        transact=lambda pkt,**kw:order.append(('netlink',HDR.unpack_from(pkt)[1])) or {'mock':True}
        with patch('nb_userns.os.getuid',return_value=70001,create=True):
            value=perform({'pid':42},'nbdl1','nbdp1',syscalls=ops,transact=transact,task_count=1)
        return value,order

    def test_single_thread_gate_precedes_syscalls(self):
        ops=Mock()
        with self.assertRaises(ValueError):perform({'pid':42},'nbdl1','nbdp1',syscalls=ops,task_count=2)
        self.assertEqual(ops.mock_calls,[])

    def test_full_required_sequence(self):
        _,order=self.run_sequence()
        self.assertEqual(order,[('netlink',18),('unshare',0),('clone',True),('clone',False),
            ('unshare',NEWUSER),('map',70001),('unshare',NEWNET),('netlink',16)])

    def test_send_attempt_occurs_after_user_map_or_net_failure(self):
        for user,mapping,net in ((-1,0,0),(0,-1,0),(0,0,-1)):
            with self.subTest(values=(user,mapping,net)):
                result,order=self.run_sequence(user,mapping,net)
                self.assertEqual(order[-1],('netlink',16))
                self.assertEqual('uid_map' in result['calls'],user==0)
                self.assertEqual('unshare_net' in result['calls'],user==0 and mapping==0)

    @patch('nb_userns.signal.SIGCHLD', 17, create=True)
    def test_namespace_children_reaped_and_child_exit_is_immediate(self):
        ops=Syscalls.__new__(Syscalls);ops.call=Mock(return_value={'rc':123,'errno':0})
        with patch('nb_userns.os.waitpid',return_value=(123,0),create=True) as wait:
            self.assertTrue(ops.clone(False)['reaped']);wait.assert_called_once_with(123,0)
        ops.call.return_value={'rc':0,'errno':0}
        with patch('nb_userns.os._exit',side_effect=SystemExit(0)) as end,self.assertRaises(SystemExit):ops.clone(True)
        end.assert_called_once_with(0)


class ReportTests(unittest.TestCase):
    def test_expected_block_diagnostics_and_raw_decode(self):
        q=req();r=report(q);self.assertEqual(validate(r,q,70001),r);self.assertTrue(blocked(r))

    def test_undefended_and_same_uid_control_report_validation(self):
        for uid in (1000,70099):
            q=req('undefended');r=report(q,True,uid=uid)
            self.assertEqual(validate(r,q,uid),r);self.assertFalse(blocked(r))

    def test_foreign_nonce_uid_pid_threads_missing_calls(self):
        for field,value in (('nonce','bad'),('original_uid',1),('pid',0),('task_count',2),('calls',{})):
            q=req();r=report(q);r[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):validate(r,q,70001)

    def test_incomplete_forged_or_trailing_raw_netlink_is_invalid(self):
        for mode in ('request','errno','missing','trailing','io','control','reap'):
            q=req();r=report(q)
            if mode=='request':r['netlink']['request_hex']=dump(1).hex()
            if mode=='errno':r['netlink']['ack_errno']=0
            if mode=='missing':r['netlink']['replies_hex']=[]
            if mode=='trailing':r['netlink']['replies_hex']+=r['netlink']['replies_hex']
            if mode=='io':r['netlink']['complete']=False
            if mode=='control':r['control']['links']=[]
            if mode=='reap':r['calls']['clone']={'rc':123,'errno':0}
            with self.subTest(mode=mode),self.assertRaises(ValueError):validate(r,q,70001)
