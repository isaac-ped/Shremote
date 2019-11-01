from paramiko import SSHClient
from checked_process import get_name_from_cmd, monitor_wait, \
                            monitor_process, launch_process_monitor
import shlex

class RemoteProccessException(CheckedProcessException):
    pass

class RemoteProcess(object):

    STOPPABLE = False

    def __init__(self, client, name, cmd, error_event):
        self.name = name
        self.client = client
        self.cmd = cmd
        self.exited = False
        self.error_event = error_event
        self.monitor_thread = None
        self.first_line = None

    def wait(self, seconds):
        if monitor_wait(self.error_event, seconds) :
            log_warn("Error encountered in other thread while executing %s" % self.name)
    
    def start(self):
        self.stdin, self.stdout, self.stderr = self.client.exec_command(self.cmd)

    def monitor(self, deamon = False, **kwargs):
        self.monitor_thread = launch_process_monitor(daemon, self, **kwargs)

    def join(self):
        return self.monitor_thread.join()

    def log_output(self):
        if self.client.recv_ready():
            data = self.client.recv(1024)
            if first_line is None:
                self.first_line = data.split('\n')[0]
            log("{} - {}:{}".format(self.name, "stdout", data))
        if self.client.recv_stderr_ready():
            log("{} - {}:{}".format(self.name, "stderr", self.client.recv_stderr(1024)))

    def poll(self, valid_rtn = None):
        exited = self.client.exit_status_ready()
        self.log_output()
        if not exited:
            return None
        self.exited = True
        rtn = self.client.recv_exit_status()
        if valid_rtn is not None:
            if rtn != valid_rtn:
                log_error("Command:\n\t%s\nReturned: %d\nExpected: %d\n" %
                          (self.args, rtn_code, valid_rtn),
                          "If this is not an error, add `checked_rtn: None` to command")
                return RemoteProccessException(self.name)
        return rtn


def insert_exec(cmd):
    split_cmd = list(shlex.shlex(cmd))
    for i, part in enumerate(split_cmd[::-1], 1):
        if part in ('&&', '||', ';'):
            split_cmd.insert(-i, 'exec')
    return 'echo $$ && ' + ' '.join(split_cmd)

def start_remote_process(cmd, ssh_cfg, addr, error_event, **kwargs):
    client = SSHClient()
    client.load_system_host_keys()
    client.connect(addr, **ssh_cfg)

    with_exec = insert_exec(cmd)
    name = get_name_from_cmd(cmd)

    remote_proc = RemoteProcess(client, name, with_exec)
    remote_proc.start()
    remote_proc.monitor()

    return remote_proc
