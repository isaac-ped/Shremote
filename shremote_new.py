#!/usr/bin/env python
from __future__ import print_function

from checked_process import shell_call, start_shell_call, start_ssh_call
from cfg_loader import load_cfg_file
from include_loader import IncludeLoader
from logger import * # log*(), set_logfile(), close_logfile()

import threading # For threading.Event
import argparse
import pprint
import os
import json
import signal
import itertools

class ShException(Exception):
    pass

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
            'rsync -av -e "ssh -p {ssh.port} -i {ssh.key}" "{dst}" "{ssh.user}@{addr}:{src}"'

    def __init__(self, cfg):
        self.name = cfg.name.format()
        self.addr = cfg.addr.format()
        self.ssh = cfg.ssh
        self.cfg = cfg
        label = cfg.get_root().label.format()
        self.log_dir = os.path.join(cfg.log_dir.format(), label)

    def __eq__(self, other):
        return self.addr == other.addr and self.log_dir == other.log_dir

    def __hash__(self):
        return hash(self.addr + self.log_dir)

    def copy_from(self, src, dst, background=False):
        cmd = self.RSYNC_FROM_CMD.format(src = src, dst = dst, addr = self.addr, ssh = self.ssh)
        if background:
            exec_fn = start_shell_call
        else:
            exec_fn = shell_call
        return exec_fn(cmd, auto_shlex=True, checked_rtn = 0)

    def copy_to(self, src, dst, background=False):
        self.exec_cmd('mkdir -p %s' % os.path.dirname(dst), background=False, checked_rtn = 0)

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
        return exec_fn(start, self.ssh, self.addr, stop_event = event, **kwargs)

class ShFile(object):

    def __init__(self, cfg, local_out):
        self.name = cfg.name.format()
        self.hosts = [ShHost(h) for h in cfg.hosts]
        self.local_out = os.path.join(local_out, cfg.get_root().label.format())
        self.cfg_src = cfg.src
        self.cfg_dst = cfg.dst

    def copy_to_host(self):
        for host in self.hosts:
            src = self.cfg_src.format(out_dir = self.local_out, host = host.cfg)
            dst = self.cfg_dst.format(out_dir = host.log_dir, host = host.cfg)
            host.copy_to(src, dst, background=False)

class ShLog(object):

    DIRS_COPIED = set()

    def __init__(self, cfg):
        self.subdir = cfg.dir

        if 'out' in cfg:
            self.out = cfg.out
        else:
            self.out = None

        if 'err' in cfg:
            self.err = cfg.err
        else:
            self.err = None

    def assert_no_overlap(self, other):
        if not self.subdir.format(host_idx=0) == other.subdir.format(host_idx=0):
            return

        if self.out is not None:
            if self.out.format(host_idx=0) == other.out.format(host_idx=0):
                raise ShException("Overlapping output log file: {}".format(self.out.format(host_idx=0)))

        if self.err is not None:
            if self.err.format(host_idx=0) == other.err.format(host_idx=0):
                raise ShException("Overlapping error log file: {}".format(self.err.format(host_idx=0)))

    def log_dir(self, host, host_idx):
        return os.path.join(host.log_dir, self.subdir.format(host_idx=host_idx))

    def suffix(self, host, host_idx):
        suffix = ''
        if self.out is not None:
            suffix += ' > {}'.format(os.path.join(host.log_dir,
                                                  self.subdir.format(host_idx = host_idx,
                                                                     host = host.cfg),
                                                  self.out.format(host_idx = host_idx,
                                                                  host = host.cfg)))
        if self.err is not None:
            suffix += ' 2> {}'.format(os.path.join(host.log_dir,
                                                   self.subdir.format(host_idx = host_idx,
                                                                      host = host.cfg),
                                                   self.err.format(host_idx = host_idx,
                                                                   host = host.cfg)))
        return suffix

    def remote_directories(self, hosts):
        dirs = set()
        for i, host in enumerate(hosts):
            dirs.add((host, os.path.join(host.log_dir, self.subdir.format(host_idx = i))))
        return dirs

    def copy_local(self, hosts, local_dir, event = None, background=False):
        threads = []

        for i, host in enumerate(hosts):
            remote_out = os.path.join(host.log_dir, self.subdir.format(host_idx = i))

            if (host.addr, remote_out) in self.DIRS_COPIED:
                continue

            shell_call(["mkdir", "-p", local_dir],
                       checked_rtn = 0, raise_error=True, stop_event = event)

            threads.append(host.copy_from(remote_out, local_dir, background=True))

            self.DIRS_COPIED.add((host.addr, remote_out))

        if background:
            return threads
        else:
            for thread in threads:
                thread.join()

class ShProgram(object):

    def __init__(self, cfg):
        self.name = cfg.name.format()
        self.log = ShLog(cfg.log)
        self.start = cfg.start
        self.stop = cfg.get('stop', None)
        self.shorter_error = cfg.duration_reduced_error.format()
        self.longer_error = cfg.duration_exceeded_error.format()
        self.checked_rtn = cfg.checked_rtn.format()
        self.background = cfg.bg.format()

    def start_cmd(self, host, host_idx):
        log_dir = self.log.log_dir(host, host_idx)
        return self.start.format(host_idx = host_idx,
                                 log_dir = log_dir,
                                 host = host.cfg) +\
                self.log.suffix(host, host_idx)

    def stop_cmd(self, host_idx):
        if self.stop is not None:
            return self.stop.format(host_idx = host_idx)
        else:
            return None

class ShCommand(object):

    def __init__(self, cfg, event):
        self.cfg = cfg
        self.event = event
        self.begin = cfg.begin.format()
        self.program = ShProgram(cfg.program)
        self.hosts = [ShHost(x) for x in cfg.hosts]
        self.max_duration = cfg.max_duration.format()
        self.min_duration = cfg.min_duration.format()

        if self.min_duration and not self.program.shorter_error:
            log_warn("Min duration specified but shorter_duration_error is false for: {}"
                     .format(self.pformat()))
            self.min_duration = None

    def get_logs(self, local_dir, event=None):
        return self.program.log.copy_local(self.hosts, local_dir, background=True, event=event)

    def remote_log_directories(self):
        return self.program.log.remote_directories(self.hosts)

    def raw(self):
        self_dict = self.cfg.get_raw()
        if 'host' in self_dict['program']:
            del self_dict['program']['host']
        return self_dict

    def pformat(self):
        return pprint.pformat(self.raw())

    def check_overlapping_logs(self, other):
        try:
            self.program.log.assert_no_overlap(other.program.log)
        except ShException:
            log_error("Instances of two commands log to the same file, and will clobber each other:")
            log_error(self.pformat())
            log_error(other.pformat())
            raise

    def validate(self):
        for host in self.hosts:
            try:
                start_cmd = self.program.start_cmd(host, 0)
            except KeyError as e:
                log_error("Error validating command %s: %s" % (self.program.start.get_raw(), e))
                raise

        try:
            stop_cmd = self.program.stop_cmd(0)
        except KeyError as e:
            log_error("Error validating command %s: %s" % (self.program.stop.get_raw(), e))
            raise

        if (stop_cmd is None) != (self.max_duration is None):
            log_error("If one of stop_cmd and max_duration is specified, "
                      "the other should be as well: {}".format(start_cmd))
            raise Exception("Cannot specify one of stop_cmd and max_duration")

        if self.program.background and self.max_duration is not None and stop_cmd is None:
            log_error("Must specify stop_cmd if program is backgrounded "
                      "and max_duration is specified: {}".format(start_cmd))
            raise Exception("Program would not be stoppable")

        if self.program.background and self.min_duration is not None:
            log_error("Cannot specify min_duration for a backgrounded program: {}"
                      .format(start_cmd))

    def start(self, log_entry):
        threads = []
        for i, host in enumerate(self.hosts):
            host_log_entry = {}
            start_cmd = self.program.start_cmd(host, i)
            stop_cmd = self.program.stop_cmd(i)

            host_log_entry['addr_'] = host.addr
            host_log_entry['start_'] = start_cmd
            host_log_entry['stop_'] = stop_cmd
            host_log_entry['time_'] = float(time.time())

            log_info("Executing on %s : %s" % (host.addr, start_cmd))
            if not self.program.background:
                t = host.exec_cmd(start_cmd, self.event,
                                  background=True, daemon=True,
                                  stop_cmd = stop_cmd,
                                  min_duration = self.min_duration,
                                  max_duration = self.max_duration,
                                  duration_exceeded_error = self.program.longer_error,
                                  checked_rtn = self.program.checked_rtn,
                                  log_end = True)
                threads.append(t)
            else:
                start_name = start_cmd.split()[0]
                t = host.exec_cmd(start_cmd, self.event,
                                  background=True, daemon=True,
                                  checked_rtn = self.program.checked_rtn, max_duration = self.max_duration,
                                  log_end = True)
                threads.append(t)

                sleep_stop_cmd = 'sleep {}; {}'.format(self.max_duration, stop_cmd)
                stop_sleep_cmd = 'pkill sleep'
                t = host.exec_cmd(sleep_stop_cmd, self.event,
                                  background=True, daemon=True,
                                  stop_cmd = stop_sleep_cmd,
                                  min_duration = self.max_duration,
                                  max_duration = self.max_duration + 1,
                                  log_end = True, name = 'stop %s' % start_name)
                threads.append(t)

            host_log_entry.update(self.raw())
            log_entry.append(host_log_entry)

        return threads

class ShRemote(object):

    def sigint_handler(self, signal, frame):
        log_error("CTRL+C PRESSED!")
        self.event.set()

    def __init__(self, cfg_file, label, out_dir, args_dict):
        self.event = threading.Event()
        signal.signal(signal.SIGINT, self.sigint_handler)

        self.output_dir = os.path.join(out_dir, label, '')
        log("Making output directory: %s" % self.output_dir)
        shell_call('mkdir -p "%s"' % self.output_dir, auto_shlex=True, checked_rtn = 0)
        set_logfile(os.path.join(self.output_dir, 'shremote.log'))
        log("Made output dir")

        self.cfg_file = cfg_file
        log("Loading %s" % cfg_file)
        self.cfg = load_cfg_file(cfg_file)

        self.cfg.args = args_dict
        self.cfg.label = label
        self.cfg.user = os.getenv('USER')
        log("Assuming user is : %s" % self.cfg.user)

        self.label = label


        commands = [ShCommand(cmd, self.event) for cmd in self.cfg.commands]
        self.commands = sorted(commands, key = lambda cmd: cmd.begin)

        self.init_cmds = [ShLocalCmd(cmd, self.event) for cmd in self.cfg.get('init_cmds', [])]
        self.post_cmds = [ShLocalCmd(cmd, self.event) for cmd in self.cfg.get('post_cmds', [])]

        self.event_log = []

        self.files = []
        for cfg in self.cfg.get('files', {}).values():
            self.files.append(ShFile(cfg, self.output_dir))

        self.validate()

    def validate(self):
        for cmd in self.commands:
            cmd.validate()

        for cmd1, cmd2 in itertools.combinations(self.commands, 2):
            cmd1.check_overlapping_logs(cmd2)

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
        remote_dirs = set()
        for cmd in self.commands:
            remote_dirs |= cmd.remote_log_directories()

        log_info("About to delete the following directories:")
        for host, remote_dir in remote_dirs:
            log_info("%s: %s" % (host.addr, remote_dir))

        time.sleep(5)

        threads = []
        event = threading.Event()
        for host, remote_dir in remote_dirs:
            del_cmd = 'rm -rf %s' % remote_dir
            threads.append(host.exec_cmd(del_cmd, event=event, background=True, checked_rtn = 0))

        for thread in threads:
            thread.join()

        if event.is_set():
            log_error("Error deleting remote logs!")

    def mk_remote_dirs(self):
        remote_dirs = set()
        for cmd in self.commands:
            remote_dirs |= cmd.remote_log_directories()

        threads = []
        event = threading.Event()
        for host, remote_dir in remote_dirs:
            mkdir_cmd = 'mkdir -p %s' % remote_dir
            threads.append(host.exec_cmd(mkdir_cmd, event = event, background=True, checked_rtn = 0))

        for thread in threads:
            thread.join()

        if event.is_set():
            raise Exception("Error making remote directories")

    def get_logs(self):
        threads = []
        event = threading.Event()
        for cmd in self.commands:
            threads.extend(cmd.get_logs(self.output_dir))

        for thread in threads:
            thread.join()

        if event.is_set():
            log_error("Error encountered getting logs!")

        shell_call(['cp', self.cfg_file, self.output_dir], raise_error=True)
        shell_call(['cp', self.cfg_file, os.path.join(self.output_dir, 'shremote_cfg.yml')], raise_error=True)
        for filename in set(IncludeLoader.included_files):
            shell_call(['cp', filename, self.output_dir], raise_error=True)

        with open(os.path.join(self.output_dir, 'event_log.json'), 'w') as f:
            json.dump(self.event_log, f, indent=2)

    def run_commands(self):
        if self.event.is_set():
            log_error("Not running commands! Execution already halted")
            return
        min_begin = self.commands[0].begin
        start_time = time.time() - min_begin

        elapsed = 0
        last_begin = 0
        max_end = 0

        for cmd in self.commands:
            elapsed = time.time() - start_time
            delay = cmd.begin - elapsed

            if delay > 0:
                log("Sleeping for %d" % delay)
                if self.event.wait(delay):
                    log_error("Error encountered in other thread! Stopping execution")
                    return
            elif last_begin != cmd.begin and delay > .1:
                log_warn("Falling behind on execution by %.1f s" % delay)

            last_begin = cmd.begin
            cmd.start(self.event_log)

            max_end = max(max_end, cmd.begin + \
                                    max(cmd.max_duration if cmd.max_duration is not None else 0,
                                        cmd.min_duration if cmd.min_duration is not None else 0))

        elapsed = time.time() - start_time
        delay = max_end - elapsed
        if self.event.wait(delay):
            log_error("Error encountered in other thread during final wait period!")
            time.sleep(5)

    def stop(self):
        self.event.set()

    def run(self):
        self.mk_remote_dirs()
        self.run_init_cmds()
        self.copy_files()
        self.run_commands()
        self.get_logs()
        self.run_post_cmds()

        log_info("Done with test!")
        close_logfile()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Schedule remote commands over SSH")
    parser.add_argument('cfg_file', type=str, help='.yml cfg file')
    parser.add_argument('label', type=str, help='Label for resulting logs')
    parser.add_argument('--parse-test', action='store_true', help='Only test parsing of cfg')
    parser.add_argument('--get-only', action='store_true', help='Only get log files, do not run')
    parser.add_argument('--out', type=str, default='.', help="Directory to output files into")
    parser.add_argument('--delete-remote', action='store_true', help='Deletes remote log directories')
    parser.add_argument('--args', type=str, required=False,
                        help="Additional arguments for yml (format 'k1:v1;k2:v2')")

    args = parser.parse_args()

    sh_args = {}
    if args.args is not None:
        for entry in args.args.split(';'):
            k, v = entry.split(":")
            sh_args[k] = v

    shremote = ShRemote(args.cfg_file, args.label, args.out, sh_args)

    if args.parse_test:
        exit(0)
    if args.get_only:
        shremote.get_logs()
    else:
        if args.delete_remote:
            shremote.delete_remote_logs()
        shremote.run()
