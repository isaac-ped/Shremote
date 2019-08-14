import time
import subprocess
import shlex
import traceback
from logger import *
from threading import Thread
from fmt_config import CfgFormatException

try:
    from queue import Queue, Empty
except:
    from Queue import Queue, Empty

class CheckedProcessException(Exception):
    pass

class CheckProc(object):

    #https://stackoverflow.com/questions/375427/non-blocking-read-on-a-subprocess-pipe-in-python
    @staticmethod
    def monitor_stream(stream, queue):
        for line in iter(stream.readline, b''):
            queue.put(line)

    def log_from_queue(self, queue, label):
        while True:
            try:
                line = queue.get_nowait()
                log("{} - {}:{}".format(self.name, label, line), end='')
            except Empty:
                break


    def log_output(self):
        self.log_from_queue(self.stderr_q, "stderr")
        self.log_from_queue(self.stdout_q, "stdout")

    def __init__(self, args, name='', shell=False):
        self.args = args
        self.name = name
        self.proc = subprocess.Popen(args, stdout = subprocess.PIPE, stderr=subprocess.PIPE, shell=shell, close_fds=True)
        self.stderr_q = Queue()
        self.stdout_q = Queue()
        self.stderr_thread = Thread(target = self.monitor_stream,
                                    args = (self.proc.stdout, self.stdout_q))
        self.stderr_thread.start()
        self.stdout_thread = Thread(target = self.monitor_stream,
                                    args = (self.proc.stderr, self.stderr_q))
        self.stdout_thread.start()

    def poll(self, valid_rtn = None):
        rtn_code = self.proc.poll()
        self.log_output()
        if rtn_code is not None:
            self.stderr_thread.join()
            self.stdout_thread.join()

            if valid_rtn is not None:
                if rtn_code != valid_rtn:
                    log_error("Command:\n\t%s\nReturned: %d\nExpected: %d\n" %
                              (self.args, rtn_code, valid_rtn),
                              "If this is not an error, add `checked_rtn: None` to command")
                    raise CheckedProcessException(self.args)

        return rtn_code

    def terminate(self):
        self.proc.terminate()

    def force_stop(self):
        try:
            self.proc.terminate()
        except OSError:
            pass
        time.sleep(.05)
        if self.poll() is None:
            log_warn("Forced to kill prcess")
            self.proc.kill()
            time.sleep(.25)
            if self.poll() is None:
                log_error("Could not terminate process!")
                return

CHECK_CALL_INTERVAL= .2

def ssh_args(ssh_cfg, cmd, addr):
    return ['ssh',
            '-p', str(ssh_cfg.port),
            '-i', str(ssh_cfg.key),
            '%s@%s' % (ssh_cfg.user, addr),
            cmd]


def shell_call(args, shell=False, auto_shlex=False,
                 stop_cmd = None, stop_event=None,
                 min_duration=None, max_duration=None,
                 duration_exceeded_error=False, checked_rtn=None,
                 raise_error=True, check_interval=CHECK_CALL_INTERVAL,
                 log_end = False, name = None):
    if auto_shlex:
        if isinstance(args, str):
            args = shlex.split(args)

    if name is None:
        if isinstance(args, list):
            name = args[0]
        else:
            name = args.split()[0]

    try:
        proc = CheckProc(args, name, shell=shell)
    except OSError as e:
        log_error("Process resulted in OSError %s: %s" % (e, args))
        log_error(traceback.format_exc())
        if stop_event is not None:
            stop_event.set()
        if raise_error:
            raise
        return

    start = time.time()
    while True:
        duration = time.time() - start
        try:
            rtn_code = proc.poll(checked_rtn)
        except CheckedProcessException as e:
            if stop_event is not None:
                stop_event.set()
            if raise_error:
                raise
            else:
                break

        if rtn_code is not None:
            break

        if max_duration is not None and duration > max_duration:
            if stop_cmd is not None:
                shell_call(stop_cmd, auto_shlex=True, check_interval = .05)
                time.sleep(.1)
            else:
                proc.terminate()
                time.sleep(.05)
            try:
                rtn_code = proc.poll(checked_rtn)
            except CheckedProcessException:
                if stop_event is not None:
                    stop_event.set()
                if raise_error:
                    raise
                return
            if rtn_code is None:
                if stop_cmd is not None:
                    log_warn("Attempt to stop command\n\t{} with\n\t{}\ndid not succeed!"
                             .format(args, stop_cmd))
                proc.force_stop()
            if duration_exceeded_error:
                log_error("Duration of {} seconds exceeded for process {}"
                          .format(max_duration, args))
                if stop_event is not None:
                    stop_event.set()
                if raise_error:
                    raise CheckedProcessException("Duration {} exceeded for process {}"
                                                  .format(max_duration, args))
                return

        if max_duration is not None:
            sleep_duration = min(max_duration - duration, check_interval)
            sleep_duration = max(sleep_duration, .05)
        else:
            sleep_duration = check_interval

        if stop_event is not None:
            if stop_event.wait(sleep_duration):
                log_warn("Error encountered in other thread while executing %s" % args)
                # Give it a chance to stop normally with the stop_cmd
                if stop_cmd is not None:
                    log("Attempting to gracefully kill {} with {}".format(name, stop_cmd))
                    shell_call(stop_cmd, auto_shlex=True, check_interval = .05)
                    time.sleep(.1)
                if proc.poll() is None:
                    log("Attempt to gracefully kill {} was unsuccessful".format(name))
                    # Then forcefully kill it in case it is still running
                    proc.force_stop()
                else:
                    log("Graceful kill of {} succeded".format(name))
        else:
            time.sleep(sleep_duration)

    if min_duration is not None and duration < min_duration:
        log_error("Command \"", name, "\" executed for ", duration,
                  "seconds; expected: ", min_duration)
        stop_event.set()
    elif log_end:
        log("Command ", name, " executed for ", duration, " seconds")

def ssh_call(cmd, ssh_cfg, addr, stop_cmd = None, stop_event = None, name = None, **kwargs):
    log("Host %s executing: %s" % (addr, cmd))
    try:
        args = ssh_args(ssh_cfg, cmd, addr)
    except Exception as e:
        if stop_event is not None:
            stop_event.set()
        log_error("Error getting ssh arguments for command %s: %s" % (cmd, e))
        return

    if name is None:
        name = "'%s' on '%s'" % (cmd.split()[0], addr)

    if stop_cmd is not None:
        stop_args = ssh_args(ssh_cfg, stop_cmd, addr)
    else:
        stop_args = None

    return shell_call(args, stop_cmd=stop_args, stop_event = stop_event, name = name, **kwargs)

def start_shell_call(*args, **kwargs):
    daemon = kwargs.get('daemon', False)
    if 'daemon' in kwargs:
        del kwargs['daemon']
    if kwargs.get('raise_error', False):
        log_warn("Raising errors on backgrounded calls is not recommended")
    else:
        kwargs['raise_error'] = False
    t = Thread(target = shell_call, args=args, kwargs=kwargs)
    t.daemon = daemon
    t.start()
    return t

def start_ssh_call(cmd, ssh_cfg, addr, stop_cmd=None, daemon=False, **kwargs):
    if kwargs.get('raise_error', False):
        log_warn("Raising errors on backgrounded calls is not recommended")
    else:
        kwargs['raise_error'] = False
    t = Thread(target = ssh_call, args=(cmd, ssh_cfg, addr, stop_cmd), kwargs=kwargs)
    t.daemon = daemon
    t.start()
    return t
