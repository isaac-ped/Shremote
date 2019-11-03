from paramiko import SSHClient
from .checked_process import get_name_from_cmd, monitor_wait, \
                              monitor_process, CheckedProcessException
from .logger import *
from threading import Thread
import shlex

class RemoteProccessException(CheckedProcessException):
    pass

class RemoteProcess(object):

    STOPPABLE = False

    def __init__(self, client, name, cmd, error_event, log_entry):
        self.name = name
        self.client = client
        self.cmd = cmd
        self.exited = False
        self.joined = False
        self.error_event = error_event
        self.monitor_thread = None
        self.first_line = None
        self.log_entry = log_entry

    def wait(self, seconds):
        if monitor_wait(self.error_event, seconds) :
            log_warn("Error encountered in other thread while executing %s" % self.name)
            return True
        return False

    def start(self):
        self.stdin, self.stdout, self.stderr = self.client.exec_command(self.cmd)

    def run_process_monitor(self, **kwargs):
        try:
            monitor_process(self, **kwargs)
            while not self.exited and self.poll() is None:
                time.sleep(.1)
        except:
            if self.error_event:
                self.error_event.set()
            while not self.exited and self.poll() is None:
                time.sleep(.1)
            raise

    def monitor(self, daemon = False, **kwargs):
        self.monitor_thread = Thread(target = self.run_process_monitor,
                                     kwargs=kwargs)
        self.monitor_thread.daemon = daemon
        self.monitor_thread.start()
        return self.monitor_thread

    def join(self):
        joined = True
        self.monitor_thread.join()
        self.exited = True
        self.client.close()

    def log_output(self):
        if self.stdout.channel.recv_ready():
            data = self.stdout.channel.recv(1024).decode('utf-8')
            if self.first_line is None:
                self.first_line = data.split('\n')[0]
                # Do not print first line, which should be PID
                data = '\n'.join(data.split('\n')[1:])
            if len(data):
                log("{} - {}:{}".format(self.name, "stdout", data))
        if self.stderr.channel.recv_stderr_ready():
            log("{} - {}:{}".format(self.name, "stderr", self.stderr.channel.recv(1024).decode('utf-8')))

    def poll(self):
        exited = self.stdout.channel.exit_status_ready()
        self.log_output()
        if not exited:
            return None
        self.exited = True
        if self.log_entry is not None:
            self.log_entry['stop_time_'] = float(time.time())
        rtn = self.stdout.channel.recv_exit_status()
        return rtn


def insert_exec(cmd):
    split_cmd = shlex.split(cmd)
    for i, part in enumerate(split_cmd[::-1], 1):
        if part in ('&&', '||', ';'):
            split_cmd.insert(-i, 'exec')
            break
    else:
        split_cmd.insert(0, 'exec')
    return 'echo $$ && ' + ' '.join(split_cmd)

def start_remote_process(cmd, ssh_cfg, addr, error_event, log_entry, name, **kwargs):
    client = SSHClient()
    client.load_system_host_keys()
    client.connect(addr, username=ssh_cfg['user'].format(), port = ssh_cfg['port'].format())

    with_exec = insert_exec(cmd)
    if name is None:
        name = get_name_from_cmd(cmd)

    remote_proc = RemoteProcess(client, name, with_exec, error_event, log_entry)
    remote_proc.start()
    remote_proc.monitor(**kwargs)

    return remote_proc
