"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from contextlib import contextmanager
import signal
import time
from env import Deadline


def until(end, clock=time.monotonic):
    left = end - clock()
    if not 0 < left <= 600:
        raise TimeoutError('batch deadline exhausted or invalid')
    value = Deadline(left, clock=clock)
    value.end = end
    return value


@contextmanager
def alarm(end):
    """Main-thread wall-clock cap also covers Python adapters and file operations.
    Outer launcher remains the independent 600 s watchdog. Offline tests mock
    this context; it never creates processes, namespaces or listeners.
    """
    if not hasattr(signal, 'setitimer'):
        raise RuntimeError('Linux wall-clock timer required')
    previous = signal.getsignal(signal.SIGALRM)
    old_delay, old_interval = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()
    left = end - started
    if left <= 0:
        raise TimeoutError('deadline exhausted')
    def expired(_signal, _frame):
        raise TimeoutError('controller wall-clock deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(left, old_delay) if old_delay else left)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if old_delay:
            signal.setitimer(signal.ITIMER_REAL, max(.000001, old_delay - (time.monotonic() - started)), old_interval)
