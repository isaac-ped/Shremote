#!/usr/bin/env python3

from __future__ import print_function

from shlib.local_process import start_local_process, exec_locally
from shlib.remote_process import start_remote_process
from shlib.cfg_format import load_cfg
from shlib.fmt_config import CfgFormatException
from shlib.include_loader import IncludeLoader
from shlib.logger import * # log*(), set_logfile(), close_logfile()

from shlib.cfg_format_v0 import likely_v0_cfg, load_v0_cfg

from collections import namedtuple
import sys
import re
import threading # For threading.Event
import argparse
import pprint
import os
import json
import signal
import itertools
import textwrap
import time

class ShException(Exception):
    pass

class ShLocalCmd(object):

    def __init__(self, cfg, event=None):
        self.cmd = cfg.cmd.format().replace('\n', ' ')
        self.checked_rtn = cfg.checked_rtn.format()
        self.event = event

    def execute(self):
        log_info("Executing %s" % self.cmd)
        p = start_local_process(self.cmd, stop_event = self.event, shell=True,
                                checked_rtn = self.checked_rtn)
        p.join()

class ShHost(object):

    RSYNC_FROM_CMD = \
            'rsync -av -e "ssh -p {ssh.port} -i {ssh.key}" "{ssh.user}@{addr}:{src}" "{dst}"'

    RSYNC_TO_CMD = \
            'rsync -av -e "ssh -p {ssh.port} -i {ssh.key}" "{src}" "{ssh.user}@{addr}:{dst}"'

    @classmethod
    def create_host_list(cls, cfg_hosts):
        hosts = [cls(h) for h in cfg_hosts]
        return hosts

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
        p = start_local_process(cmd, None, shell=True, checked_rtn = 0)
        if not background:
            p.join()
        return p

    def copy_to(self, src, dst, background=False):
        p = start_local_process(['mkdir', '-p', dst], None, shell=False, checked_rtn = 0)
        p.join()

        cmd = self.RSYNC_TO_CMD.format(src = src, dst = dst, addr = self.addr, ssh = self.ssh)
        p = start_local_process(cmd, None, shell=True, checked_rtn = 0)
        if not background:
            p.join()
        return p

    def exec_cmd(self, cmd, event=None, background=True, log_entry = None, name = None, **kwargs):
        proc = start_remote_process(cmd, self.ssh, self.addr, event, log_entry, name, **kwargs)
        if not background:
            proc.join()
        return proc

class ShFile(object):

    def __init__(self, cfg, local_out):
        self.name = cfg.name.format()
        self.hosts = ShHost.create_host_list(cfg.hosts)
        self.local_out = os.path.join(local_out, cfg.get_root().label.format())
        self.cfg_src = cfg.src
        self.cfg_dst = cfg.dst

    def validate(self):
        for host in self.hosts:
            try:
                self.cfg_src.format(host = host.cfg)
            except (KeyError, CfgFormatException) as e:
                log_error("Error formatting source of file {}: {}".format(self.name, e))
                raise

            try:
                self.cfg_dst.format(host = host.cfg)
            except (KeyError, CfgFormatException) as e:
                log_error("Error formatting dest of file {}: {}".format(self.name, e))
                raise

    def copy_to_host(self):
        for host in self.hosts:
            src = self.cfg_src.format(host = host.cfg)
            dst = self.cfg_dst.format(host = host.cfg)
            log_info("Copying {} to host {}".format(src, host.name))
            host.copy_to(src, dst, background=False)

class ShLog(object):

    DIRS_COPIED = set()

    def __init__(self, cfg):
        self.subdir = cfg.dir
        self.do_append = cfg.append.format()

        if 'out' in cfg:
            self.out = cfg.out
        else:
            self.out = None

        if 'err' in cfg:
            self.err = cfg.err
        else:
            self.err = None

    def assert_no_overlap(self, other):
        if self.do_append and other.do_append:
            return

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
        if self.do_append:
            redir = '>>'
        else:
            redir = '>'

        suffix = ''
        if self.out is not None:
            suffix += ' {} {}'.format(redir, os.path.join(host.log_dir,
                                                  self.subdir.format(host_idx = host_idx,
                                                                     host = host.cfg),
                                                  self.out.format(host_idx = host_idx,
                                                                  host = host.cfg)))
        if self.err is not None:
            suffix += ' 2{} {}'.format(redir, os.path.join(host.log_dir,
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

            exec_locally(["mkdir", "-p", local_dir])

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

    def stop_cmd(self, host, host_idx, start_pid):
        if self.stop is not None:
            return self.stop.format(host_idx = host_idx, host = host.cfg, pid = start_pid)
        else:
            return None

class ShCommand(object):

    def __init__(self, cfg, event):
        self.cfg = cfg
        self.event = event
        self.begin = cfg.begin.format()
        self.program = ShProgram(cfg.program)
        self.hosts = ShHost.create_host_list(cfg.hosts)
        self.max_duration = cfg.max_duration.format()
        self.min_duration = cfg.min_duration.format()
        self.log_entries = []
        self.processes = []
        self.started = False
        self.stopped = False

        if self.max_duration is not None:
            self.end = self.begin + self.max_duration
        else:
            self.end = None

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
            log_error("Instances of two commands log to the same file,"
                      "and will clobber each other:")
            log_error(self.cfg.program.log.pformat())
            raise

    def validate(self):
        for i, host in enumerate(self.hosts):
            try:
                start_cmd = self.program.start_cmd(host, i)
            except KeyError as e:
                log_error("Error validating command %s: %s" % (self.program.start.get_raw(), e))
                raise

        try:
            stop_cmd = self.program.stop_cmd(self.hosts[0], 0, 'pid')
        except KeyError as e:
            log_error("Error validating command %s: %s" % (self.program.stop.get_raw(), e))
            raise

        if self.program.background and self.max_duration is not None and stop_cmd is None:
            log_error("Must specify stop_cmd if program is backgrounded "
                      "and max_duration is specified: {}".format(start_cmd))
            raise Exception("Program would not be stoppable")

        if self.program.background and self.min_duration is not None:
            log_error("Cannot specify min_duration for a backgrounded program: {}"
                      .format(start_cmd))

    def cmd_text_iter(self):
        for i, host in enumerate(self.hosts):
            start_cmd = self.program.start_cmd(host, i)
            stop_cmd = self.program.stop_cmd(host, i, '__pid__')
            yield host, start_cmd, stop_cmd

    def start_cmds(self):
        for i, host in enumerate(self.hosts):
            start_cmd = self.program.start_cmd(host, i)
            yield host, start_cmd

    def stop_cmds(self):
        for i, (proc, host) in enumerate(zip(self.processes, self.hosts)):
            stop_cmd = self.program.stop_cmd(host, i, proc.first_line)
            yield host, proc, stop_cmd

    def join(self):
        for proc in self.processes:
            if not proc.joined:
                proc.join()

    def running(self):
        if not self.started:
            return False
        return not self.exited()

    def exited(self):
        if self.program.background:
            return self.stopped
        for proc in self.processes:
            if not proc.exited:
                return False
        return True

    def stop(self, kill_pid = False):
        log("Attempting stop of", self.program.name)
        for (host, proc, stop_cmd), log_entry in zip(self.stop_cmds(), self.log_entries):
            cmd_name = "STOP %s on %s" % (self.program.name, host.name)
            if not self.program.background and proc.exited:
                log("Process %s already exited" % cmd_name)
                proc.join()
                continue

            if kill_pid:
                log("LAST ATTEMPT TO KILL %s" % cmd_name)
                host.exec_cmd("kill -9 %s" % proc.first_line, background=False,
                              name = cmd_name + "_KILL", log_end = False)
            elif stop_cmd is not None:
                host.exec_cmd(stop_cmd, background = False,
                              name = cmd_name + "_stop", log_end = False)

            if self.program.background:
                log_entry['stop_time_'] = float(time.time())

        self.stopped = True
            # NOTE: Not joining process here - might need more time to shut down
            # and don't want to block execution

    def start(self, log_entry):
        self.started = True
        max_dur = None if self.program.stop is not None else self.max_duration
        for host, start_cmd in self.start_cmds():
            cmd_name = "%s on %s" % (self.program.name, host.name)
            host_log_entry = {}

            host_log_entry['addr_'] = host.addr
            host_log_entry['start_'] = start_cmd
            host_log_entry['time_'] = float(time.time())

            log_info("Executing %s : %s" % (cmd_name, start_cmd))
            if not self.program.background:
                p = host.exec_cmd(start_cmd, self.event,
                                  background=True, log_entry = host_log_entry,
                                  name = cmd_name,
                                  min_duration = self.min_duration,
                                  max_duration = max_dur,
                                  checked_rtn = self.program.checked_rtn,
                                  log_end = True)
            else:
                p = host.exec_cmd(start_cmd, self.event,
                                  background=False,
                                  name = cmd_name,
                                  checked_rtn = self.program.checked_rtn,
                                  max_duration = max_dur,
                                  log_end = True)
            self.processes.append(p)

            host_log_entry.update(self.raw())
            self.log_entries.append(host_log_entry)
            log_entry.append(host_log_entry)

class ShRemote(object):

    CommandInstance = namedtuple("cmd_instance", ["time", "is_stop", "cmd"])

    def sigint_handler(self, signal, frame):
        if self.interrupts_attempted == 0:
            log_error("CTRL+C PRESSED!")
            self.event.set()
        if self.interrupts_attempted == 1:
            log_error("CTRL+C PRESSED AGAIN!")
            log_warn("Interrupt one more time to skip waiting for processes to finish")
        if self.interrupts_attempted ==2 :
            log_error("CTRL+C PRESSED AGAIN! Processes may now be left running!!!")
        if self.interrupts_attempted > 2:
            log_error("CTRL+C PRESSED EVEN MORE! BE PATIENT!")
        self.interrupts_attempted += 1

    def __init__(self, cfg_file, label, out_dir, args_dict, suppress_output):
        self.event = threading.Event()
        self.interrupts_attempted = 0
        signal.signal(signal.SIGINT, self.sigint_handler)

        self.output_dir = os.path.expanduser(os.path.join(out_dir, label, ''))
        log("Making output directory: %s" % self.output_dir)
        if not suppress_output:
            exec_locally(['mkdir', '-p', self.output_dir])
            set_logfile(os.path.join(self.output_dir, 'shremote.log'))
        log("Made output dir")

        self.cfg_file = cfg_file
        log("Loading %s" % cfg_file)

        try:
            self.cfg = load_cfg(cfg_file)
        except Exception:
            if likely_v0_cfg(cfg_file):
                log_warn("Exception encountered loading {}. "
                         "Attempting to fall back to older cfg format".format(cfg_file))
                self.cfg = load_v0_cfg(cfg_file)
            else:
                raise

        self.cfg.args = args_dict
        self.cfg.label = label
        self.cfg.user = os.getenv('USER')
        self.cfg.cfg_dir = os.path.dirname(cfg_file)
        self.cfg.output_dir = self.output_dir
        log("Assuming user is : %s" % self.cfg.user)

        self.label = label


        self.commands = [ShCommand(cmd, self.event) for cmd in self.cfg.commands if cmd.enabled.format()]
        self.commands = sorted(self.commands, key = lambda cmd: cmd.begin)

        self.command_instances = []
        for command in self.commands:
            self.command_instances.append(self.CommandInstance(command.begin, False, command))
            if command.end is not None:
                self.command_instances.append(self.CommandInstance(command.end, True, command))

        self.command_instances = sorted(self.command_instances, key = lambda cmd: cmd.time)

        self.init_cmds = [ShLocalCmd(cmd, self.event) for cmd in self.cfg.get('init_cmds', [])]
        self.post_cmds = [ShLocalCmd(cmd, self.event) for cmd in self.cfg.get('post_cmds', [])]

        self.event_log = []

        self.files = []
        for cfg in self.cfg.get('files', {}).values():
            if cfg.enabled.format():
                self.files.append(ShFile(cfg, self.output_dir))

    def show_args(self):
        required_args = set()
        for entry in self.cfg.children(True):
            if entry.is_leaf():
                raw = entry.get_raw()
                if isinstance(raw, str) and '{0.args.' in raw:
                    for arg in re.findall('(?<={0.args.).+?(?=})', raw):
                        required_args.add(arg)

        log_info("Specified file requires the following command line arguments: {}"
                 .format(', '.join(list(required_args))))

    def validate(self):
        for cmd in self.commands:
            cmd.validate()

        for cmd1, cmd2 in itertools.combinations(self.commands, 2):
            cmd1.check_overlapping_logs(cmd2)

        for file in self.files:
            file.validate()

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
        log_info("Copying logs into {}".format(self.output_dir))
        threads = []
        event = threading.Event()
        for cmd in self.commands:
            threads.extend(cmd.get_logs(self.output_dir))

        for thread in threads:
            thread.join()

        if event.is_set():
            log_error("Error encountered getting logs!")

        exec_locally(['cp', self.cfg_file, self.output_dir])
        exec_locally(['cp', self.cfg_file, os.path.join(self.output_dir, 'shremote_cfg.yml')])
        for filename in set(IncludeLoader.included_files):
            exec_locally(['cp', filename, self.output_dir])

        with open(os.path.join(self.output_dir, 'event_log.json'), 'w') as f:
            json.dump(self.event_log, f, indent=2)

    def show_commands(self):
        cmds_summary = []
        for cmd in self.commands:
            cmd_summary = ['Time: {}'.format(cmd.begin)]
            if cmd.max_duration is not None:
                cmd_summary.append('Duration: {}'.format(cmd.max_duration))
            if cmd.min_duration is not None:
                cmd_summary.append('Minimum Duration: {}'.format(cmd.min_duration))
            for host, start, stop in cmd.cmd_text_iter():
                host_summary = ['Host: {}'.format(host.name)]
                wrapped = textwrap.wrap(start, break_on_hyphens=False)
                start = ' \\\n\t\t\t'.join(wrapped)
                host_summary.append('Start: {}'.format(start))
                if stop is not None:
                    host_summary.append('Stop: {}'.format(stop))
                cmd_summary.append('\n\t\t'.join(host_summary))
            cmds_summary.append('\n\t'.join(cmd_summary))
        log_info('\n' + '\n'.join(cmds_summary))

    def run_commands(self):
        if self.event.is_set():
            log_error("Not running commands! Execution already halted")
            return
        min_begin = self.commands[0].begin
        start_time = time.time() - min_begin

        elapsed = 0
        last_begin = 0
        max_end = 0

        for cmd_time, is_stop, cmd in self.command_instances:
            elapsed = time.time() - start_time
            delay = cmd_time - elapsed

            if delay > 0:
                log("Sleeping for %d" % delay)
                errored = False
                while delay > 0:
                    if self.event.wait(1):
                        log_warn("Error encountered in other thread! Stopping execution")
                        errored = True
                        break
                    elapsed = time.time() - start_time
                    delay = cmd_time - elapsed

                    any_running = False
                    for other_cmd in self.commands:
                        if not other_cmd.exited():
                            any_running = True
                            break

                    if not any_running:
                        log_info("Nothing left running! Ending early.")
                        break

                if errored or not any_running:
                    break

            elif last_begin != time and delay > .1:
                log_warn("Falling behind on execution by %.1f s" % delay)

            last_begin = cmd_time

            if is_stop:
                cmd.stop()
            else:
                cmd.start(self.event_log)

            max_end = max(max_end, cmd.begin + \
                                    max(cmd.max_duration if cmd.max_duration is not None else 0,
                                        cmd.min_duration if cmd.min_duration is not None else 0))

        elapsed = time.time() - start_time
        delay = max_end - elapsed
        while (delay > 0):
            if self.event.wait(1):
                log_warn("Error encountered in other thread during final wait period!")
                time.sleep(1)
                break

            for cmd in self.commands:
                if cmd.running():
                    break
            else:
                log("Commands done early")
                break

        any_running = False
        for cmd in self.commands:
            if cmd.running():
                any_running = True
                cmd.stop()

        stops_attempted = 0
        do_kill = False
        while any_running and self.interrupts_attempted <= 2:
            time.sleep(.25)
            any_running = False
            for cmd in self.commands:
                if cmd.running():
                    cmd.stop()
                    any_running = True
            stops_attempted+=1
            if stops_attempted > 20:
                do_kill = True
                break

        if do_kill:
            for cmd in self.commands:
                if cmd.running():
                    cmd.stop(True)
            time.sleep(1)
            for cmd in self.commands:
                if cmd.running():
                    log_warn("Program %s may still be running" % cmd.program.name)

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
        return self.event.is_set()

def parse_unknown_args(args):
    new_args = {}
    key = None
    value = None
    for arg in args:
        if arg.startswith('--'):
            key = arg.strip('--')
            new_args[key] = None
        else:
            new_args[key] = arg

    return new_args

def main():
    parser = argparse.ArgumentParser(description="Schedule remote commands over SSH")
    parser.add_argument('cfg_file', type=str, help='.yml cfg file')
    parser.add_argument('label', type=str, help='Label for resulting logs')
    parser.add_argument('--parse-test', action='store_true', help='Only test parsing of cfg')
    parser.add_argument('--get-only', action='store_true', help='Only get log files, do not run')
    parser.add_argument('--out', type=str, default='.', help="Directory to output files into")
    parser.add_argument('--delete-remote', action='store_true', help='Deletes remote log directories')
    parser.add_argument('--args', type=str, required=False,
                        help="Additional arguments which are passed to the config file (format 'k1:v1;k2:v2')")

    if '--' in sys.argv:
        argv = sys.argv[1:sys.argv.index('--')]
        other_args = parse_unknown_args(sys.argv[sys.argv.index('--')+1:])
    else:
        argv = sys.argv[1:]
        other_args = {}

    args = parser.parse_args(argv)

    if args.args is not None:
        for entry in args.args.split(';'):
            k, v = entry.split(":")
            other_args[k] = v

    shremote = ShRemote(args.cfg_file, args.label, args.out, other_args, args.parse_test)

    if args.parse_test:
        shremote.show_args()
        shremote.validate()
        shremote.show_commands()
        exit(0)

    shremote.validate()
    if args.get_only:
        shremote.get_logs()
    else:
        if args.delete_remote:
            shremote.delete_remote_logs()
        return shremote.run()


if __name__ == '__main__':
    exit(main())
