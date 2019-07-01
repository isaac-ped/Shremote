import unittest
import os
import time
import test_files ## Adds path to import checked_process
from checked_process import shell_call, start_shell_call, CheckedProcessException
import threading

class TestCfgLoader(unittest.TestCase):

    DURATION_CMD = 'for i in `seq 1 {}`; do echo $i; sleep .1; done'
    FOREVER_CMD = ['sleep', '100']
    KILL_FOREVER_CMD = 'pkill sleep'

    def dur_cmd(self, time):
        return self.DURATION_CMD.format(time)

    def check_duration(self, max_time, fn):
        start = time.time()
        fn()
        dur = time.time() - start

        self.assertTrue(dur < max_time, "Fn ran for too long")

    def test_simple_shell_execute(self):
        self.check_duration(.4,
                lambda: shell_call(self.dur_cmd(3), shell=True, log_end=True,
                                   check_interval=.05))


    def test_max_duration_stop_cmd(self):
        self.check_duration(.5,
                lambda: shell_call(self.FOREVER_CMD, stop_cmd = self.KILL_FOREVER_CMD,
                           max_duration = .25, log_end = True)
        )

    def test_max_duration_no_stop_cmd(self):
        self.check_duration(.5,
                lambda: shell_call(self.FOREVER_CMD,
                       max_duration = .25, log_end = True)
        )

    def test_max_duration_not_exceeded(self):
        self.check_duration(.3,
                lambda: shell_call(self.dur_cmd(2), shell=True, log_end=True,
                       max_duration=.25, duration_exceeded_error=True)
        )

    def test_max_duration_exceeded_and_thrown(self):
        event = threading.Event()
        try:
            shell_call(self.FOREVER_CMD, max_duration=.2, duration_exceeded_error=True,
                       log_end=True, check_interval=.1, stop_event = event)
        except CheckedProcessException:
            self.assertTrue(event.is_set(), "Error event was not set")
            return
        self.assertTrue(False, "Did not raise error")

    def test_max_duration_exceeded_and_not_thrown(self):
        event = threading.Event()
        shell_call(self.FOREVER_CMD, max_duration=.2, duration_exceeded_error = True,
                   log_end=True, check_interval=.1, stop_event = event,
                   raise_error=False)
        self.assertTrue(event.is_set(), "Error event was set")

    def test_start_shell_call(self):
        t = start_shell_call(self.dur_cmd(3), shell=True, check_interval=.05)
        t.join()

    def test_stop_with_event(self):
        event = threading.Event()
        t = start_shell_call(self.FOREVER_CMD, stop_cmd = self.KILL_FOREVER_CMD,
                             log_end=True, check_interval=.1, stop_event=event)
        event.set()
        self.check_duration(.1, lambda: t.join())

    def test_check_rtn_passes(self):
        shell_call(self.dur_cmd(3), shell=True, log_end=True,
                   checked_rtn = 0)

    def test_check_rtn_fails(self):
        event = threading.Event()
        try:
            shell_call(self.dur_cmd(3), shell=True, log_end=True,
                       checked_rtn = 1, stop_event=event)
        except CheckedProcessException:
            self.assertTrue(event.is_set(), "Error event not set")
            return
        self.assertTrue(False, "Did not raise error")

    def test_auto_shlex(self):
        shell_call("sleep .1", auto_shlex=True, log_end=True)

if __name__ == '__main__':
    unittest.main()
