#!/usr/bin/env python

from __future__ import print_function
from checked_process import shell_call, start_shell_call, start_ssh_call
import pprint

class LocalCmd(object):

    def __init__(self, cfg, event=None):
        self.cmd = self.cfg.cmd.format()
        self.checked_rtn = self.cfg.checked_rtn.format()
        self.event = event

    def execute(self):
        shell_call(self.cmd, shell = True, stop_event = self.event,
                   checked_rtn = self.checked_rtn)

class ShHost(object):

    RSYNC_FROM_CMD = \
            'rsync -av -e "ssh -p {ssh.port} -i {ssh.key}" "{ssh.user}@{addr}:{src}" "{dst}"'

    RSYNC_TO_CMD = \
            'rsync -av -e "ssh -p {ssh.port} -i {ssk.key}" "{dst}" "{ssh.user}@{addr}:{src}"'

    def __init__(self, cfg):
        self.addr = cfg.addr.format()
        self.ssh = cfg.ssh
        self.log_dir = cfg.log_dir.format()

    def copy_from(self, src, dst, background=False):
        cmd = self.RSYNC_FROM_CMD.format(src = src, dst = dst, addr = self.addr, ssh = self.ssh)
        if background:
            exec_fn = start_shell_call
        else:
            exec_fn = shell_call
        return exec_fn(cmd, auto_shlex=True, checked_rtn = 0)

    def copy_to(self, src, dst, background=False):
        cmd = self.RSYNC_TO_CMD.format(src = src, dst = dst, addr = self.addr, ssh = self.ssh)
        if background:
            exec_fn = start_shell_call
        else:
            exec_fn = shell_call
        return exec_fn(cmd, auto_shlex=True, checked_rtn = 0)

    def exec_cmd(self, start, event=None, background=True, **kwargs):
        if background:
            exec_fn = start_ssh_call
        else:
            exec_fn = ssh_call
        return exec_fn(start, self.ssh, stop_event = event, **kwargs)

class ShFile(object):

    def __init__(self, cfg, local_out, label):
        self.host = ShHost(cfg.host)
        self.src = cfg.src.format(out_dir = os.path.join(local_out, label))
        self.dst = cfg.dst.format(out_dir = os.path.join(cfg.host.log_dir, label))

    def copy_to_host(self):
        self.host.copy_to(self.src, self.dst, background=False)

class ShLog(object):

    DIRS_COPIED = set()

    def __init__(self, cfg, i):
        self.subdir = cfg.dir

        if 'out' in cfg:
            self.out = cfg.out
        else:
            self.out = None

        if 'err' in cfg:
            self.err = cfg.err
        else:
            self.err = None

    def suffix(self, i):
        suffix = ''
        if self.out is not None:
            suffix += ' > {}'.format(os.path.join(self.subdir.format(i=i),
                                                  self.out.format(i=i))
        if self.err is not None:
            suffix += ' 2> {}'.format(os.path.join(self.subdir.format(i=i),
                                                   self.err.format(i=i))
        return suffix

    def copy_local(self, hosts, local_dir, background=False):
        threads = []
        for i, host in enumerate(hosts):
            local_out = os.path.join(local_dir, self.subdir.format(i=i))
            remote_out = os.path.join(host.log_dir, self.subdir.format(i=i))

            if (host.addr, remote_out) in self.DIRS_COPIED:
                log("{}:{} already copied", host.addr, remote_out)
                continue

            shell_call(["mkdir", "-p", os.path.join(local_out)],
                       checked_rtn = 0, raise_error=True)

            threads.append(host.copy_from(remote_out, local_out, background=True))

            self.DIRS_COPIED.add((host.addr, remote_out))

        if background:
            return threads
        else:
            for thread in threads:
                thread.join()

class ShProgram(object):

    def __init__(self, cfg):
        self.log = ShLog(cfg.log)
        self.start = cfg.start
        self.stop = cfg.stop
        self.shorter_error = cfg.shorter_duration_error.format()
        self.longer_error = cfg.duration_exceeded_error.format()
        self.checked_rtn = cfg.checked_rtn

    def start_cmd(self, i):
        return self.start.format(i=i) + self.log.suffix(i=i)

    def stop_cmd(self, i):
        return self.stop.format(i=i)

class ShCommand(object):

    def __init__(self, cfg, event):
        self.cfg = cfg
        self.event = event
        self.begin = cfg.begin.format()
        self.program = ShProgram(cfg.program, i)
        self.hosts = [ShHost(x) for x in cfg.hosts]
        self.max_duration = cfg.max_duration.format()
        self.min_duration = cfg.min_duration.format()

        if self.min_duration and not self.program.shorter_error:
            log_warn("Min duration specified but shorter_duration_error is false for: {}"
                     .format(self.pformat()))
            self.min_duration = None

    def raw(self):
        self_dict = self.cfg.raw()
        if 'host' in self_dict['program']:
            del self_dict['program']['host']
        return self_dict

    def pformat(self):
        return pprint.pformat(self.raw())

    def start(self, log_entry):
        threads = []
        for i, host in self.hosts:
            host_log_entry = {}
            start_cmd = self.program.start_cmd(i)
            stop_cmd = self.program.stop_cmd(i)
            host_log_entry['addr_'] = host.addr
            host_log_entry['start_'] = self.start_cmd
            host_log_entry['stop_'] = self.stop_cmd
            host_log_entry['time_'] = float(time.time())

            t = host.exec_cmd(start_cmd, self.event, background=True,
                              stop_cmd = stop_cmd,
                              min_duration = self.min_duration,
                              max_duration = self.max_duration,
                              duration_exceeded_error = self.program.longer_error,
                              checked_rtn = self.program.checked_rtn)
            threads.append(t)

            host_log_entry.update(self.raw())
            log_entry.append(host_log_entry)

        return threads
