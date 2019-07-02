#!/usr/bin/env python

from __future__ import print_function
from checked_process import shell_call, start_shell_call, start_ssh_call
import pprint

class ShLocalCmd(object):

    def __init__(self, cfg, event=None):
        self.cmd = self.cfg.cmd.format().replace('\n', ' ')
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
        self.name = cfg.get_name()
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
        mkdir_cmd = 'mkdir -p %s' % os.path.dirname(dst)
        ssh_call(mkdir_cmd, self.ssh, checked_rtn = 0)

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

    def __init__(self, cfg, name, local_out, label):
        self.name = name
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
                                                  self.out.format(i=i)))
        if self.err is not None:
            suffix += ' 2> {}'.format(os.path.join(self.subdir.format(i=i),
                                                   self.err.format(i=i)))
        return suffix

    def remote_directories(self, hosts):
        dirs = set()
        for i, host in enumerate(hosts):
            dirs.add((host, os.path.join(host.log_dir, self.subdir.format(i=i))))
        return dirs

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
        self.name = cfg.get_name()
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

    def get_logs(self, local_dir):
        threads = []
        for host in self.hosts:
            threads.append(self.program.log.copy_local(host, local_dir, background=True))
        return threads

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

            t = host.exec_cmd(start_cmd, self.event, background=True, daemon=True,
                              stop_cmd = stop_cmd,
                              min_duration = self.min_duration,
                              max_duration = self.max_duration,
                              duration_exceeded_error = self.program.longer_error,
                              checked_rtn = self.program.checked_rtn)
            threads.append(t)

            host_log_entry.update(self.raw())
            log_entry.append(host_log_entry)

        return threads

class ShRemote(object):

    def __init__(self, cfg_file, label, out_dir, args_dict):
        self.output_dir = os.path.join(out_dir, label, '')

        self.cfg = load_cfg_file(cfg_file)
        self.cfg.args = args_dict
        self.cfg.label = label

        self.event = threading.Event()
        self.label = label

        shell_call('mkdir -p "%s"' % self.output_dir, auto_shlex=True, checked_rtn = 0)

        set_logfile(os.path.join(self.output_dir, 'shremote.log'))

        commands = [ShCommand(cmd, self.event) for cmd in self.cfg.commands]
        self.commands = sorted(commands, key = lambda cmd: cmd.begin)

        self.init_cmds = [ShLocalCmd(cmd, self.event) for cmd in self.cfg.get('init_cmds', [])]
        self.post_cmds = [ShLocalCmd(cmd, self.event) for cmd in self.cfg.get('post_cmds', [])]

        self.event_log = []

        self.files = []
        for name, cfg in self.cfg.get('files', {}).items():
            self.files.append(ShFile(cfg, name, self.output_dir, label))

    def run_init_cmds(self):
        for cmd in self.init_cmds:
            cmd.execute()

    def run_post_cmds(self):
        for cmd in self.post_cmds:
            cmd.execute()

    def copy_files(self):
        for file in self.files:
            file.copy_to_host()

    def delete_remote_logs(self):
        remote_dirs = set(cmd.program.log.remote_directories() for cmd in self.commands)

        log_info("About to delete the following directories:")
        for host, remote_dir in remote_dirs:
            log_info("%s: %s" % (host.addr, remote_dir))

        threads = []
        for host, remote_dir in remote_dirs:
            del_cmd = 'rm -rf %s' % remote_dir
            threads.append(host.exec_cmd(del_cmd, background=True))

        for thread in threads:
            thread.join()

    def mk_remote_dirs(self):
        remote_dirs = set(cmd.program.log.remote_directories() for cmd in self.commands)

        for host, remote_dir in remote_dirs:
            mkdir_cmd = 'mkdir -p %s' % remote_dir
            threads.append(host.exec_cmd(mkdir_cmd, background=True))

        for thread in threads:
            thread.join()

    def get_logs(self):
        threads = []
        for cmd in self.commands:
            threads.append(cmd.get_logs(self.output_dir))

        for thread in threads:
            thread.join()

        shell_call(['cp', self.cfg_file, self.output_dir], raise_error=True)
        shell_call(['cp', self.cfg_file, os.path.join(self.output_dir, 'shremote_cfg.yml')], raise_error=True)
        for filename in set(IncludeLoader.included_files):
            shell_call(['cp', filename, self.output_dir], raise_error=True)

        with open(os.path.join(self.output_dir, 'event_log.json'), 'w') as f:
            json.dump(self.event_log, f, indent=2)

    def run_commands(self):
        min_begin = self.commands[0].begin
        start_time = time.time() - min_begin

        elapsed = 0
        last_begin = 0
        max_end = 0

        for cmd in self.commands:
            elapsed = time.time() - start_time
            delay = command.begin - elapsed

            if delay > 0:
                log("Sleeping for %d" % delay)
                if self.event.wait(delay):
                    log_error("Error encountered in other thread")
                    return
            elif last_begin != cmomand.begin and delay > .1:
                log_warn("Falling behind on execution by %.1f s" % delay)

            last_begin = command.begin
            cmd.start(self.event_log)

            max_end = max(max_end, cmd.begin + \
                                    max(cmd.max_duration if cmd.max_duration is not None else 0,
                                        cmd.min_duration if cmd.min_duration is not None else 0))

        elapsed = time.time() - start_time
        delay = max_end - elapsed
        if error_event.wait(delay):
            log_error("Error encountered in other thread")

    def stop(self):
        self.event.set()

    def run(self):
        self.mk_remote_dirs()
        self.run_init_cmds()
        self.copy_files()
        self.run_command()
        self.get_logs()
        self.run_post_cmds()

        log_info("Done with test!")


