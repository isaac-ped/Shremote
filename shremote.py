from __future__ import print_function
from collections import defaultdict
import pprint
import json
import shutil
import time
import os
import sys
import subprocess
from subprocess import CalledProcessError
import yaml
import time
import re
import argparse
import copy
import signal
import traceback
from threading import Thread
import threading

COLORS = dict(
    END='\033[0m',
    WARNING = '\033[93m',
    ERROR = '\033[31m',
    INFO = '\033[0;32m'
)

test_mode = False

start_time = time.time()

LOGFILE = None

def log_(s, **print_kwargs):
    if (LOGFILE is not None):
        LOGFILE.write(s + '\n')
    print(s, **print_kwargs)

def log(*args, **kwargs):
    s = "DEBUG {:.1f}: ".format(time.time() - start_time)
    log_(s + " ".join([str(x) for x in args]), **kwargs)

def log_info(*args, **kwargs):
    s = COLORS['INFO'] + 'INFO {:.1f}: '.format(time.time() - start_time)
    log_(s + " ".join([str(x) for x in args]) + COLORS['END'], **kwargs)

def log_warn(*args, **kwargs):
    s = COLORS["WARNING"] + "WARNING: " + ' '.join([str(x) for x in args]) + COLORS['END']
    log_(s, **kwargs)

def log_error(*args, **kwargs):
    s = COLORS['ERROR'] + "\n________________________________________________\n"
    s += "ERROR: " + " ".join([str(x) for x in args])
    s += "\n________________________________________________" + COLORS['END'] + "\n"
    log_(s, **kwargs)

fatality = False
error_event = threading.Event()

def log_fatal(*args, **kwargs):
    global fatality
    if fatality:
        print("DOUBLE FATALITY: ", *args, **kwargs)
        exit(-1)

    print("\n________________________________________________")
    print("------- FATAL ERROR: ", *args, **kwargs)
    print("________________________________________________\n")

    print("Attempting to stop everything!")
    fatality = True
    try:
        if TestRunner.instance().initialized:
            TestRunner.instance().stop_all()
            TestRunner.instance().get_logs()
            TestRunner.instance().write_log()
    except:
        log_warn("Ran into error attempting to stop!")
        traceback.print_exc()
    print("Exiting")
    exit(-1)

def sigint_handler(signal, frame):
    log_fatal("CTRL+C PRESSED!!")

signal.signal(signal.SIGINT, sigint_handler)

def call(cmd, enforce_duration=None, check_return=None, raise_error=False):
    log("Executing ", cmd)
    if enforce_duration is not None:
        log("Ensuring command executes for at least %d" % enforce_duration)
    start = time.time()
    try:
        output = subprocess.check_output(cmd, shell=True)
        if len(output) > 0:
            log("Command ", cmd, "output: ", output)
    except CalledProcessError as err:
        if len(err.output) > 0:
            log("Command ", cmd, "output: ", err.output)
        if check_return is not None:
            if err.returncode != check_return:
                log_error("Command ", cmd, " returned: ", err.returncode, ". Expected: ", check_return)
                log_error(traceback.format_exc())
                error_event.set()
                if do_throw:
                    raise
    end = time.time()
    duration = end - start
    if enforce_duration is not None and test_mode == False:
        if duration < enforce_duration:
            log_error("Command  ", cmd, "executed for ", int(duration), "seconds. Expected: ", enforce_duration)
            error_event.set()

class Config(object):

    instance_ = None

    @classmethod
    def instance(cls):
        if cls.instance_ is None:
            raise Exception("Config instance not instantiated")
        return cls.instance_

    @classmethod
    def format(cls, st, **kwargs):
        if cls.instance_ is None:
            raise Exception("Config instance not instantiated")

        # TODO: Regex match, in case string contains \{
        while '{' in st:
            try:
                st = st.format(cls.instance_, **kwargs)
            except Exception as e:
                log_error("Error formatting:\n\t{}\nwith\n\t{}\nError: {}".format(st, kwargs, e))
                raise
        return st

    def __init__(self, data, **kwargs):
        if Config.instance_ is None:
            Config.instance_ = self

        self.__dict__['dict'] = {}

        load_from = data.copy()
        load_from.update(kwargs)

        for k, v in load_from.items():
            if isinstance(v, dict):
                self.dict[k] = Config(v)
            elif isinstance(v, list):
                attr = []
                for v2 in v:
                    if isinstance(v2, dict):
                        attr.append(Config(v2))
                    else:
                        attr.append(v2)
                self.dict[k] = attr
            else:
                self.dict[k] = v

    def __str__(self):
        return pprint.pformat(self.full_dict)

    @property
    def full_dict(self):
        d = {}
        for k, v in self.dict.items():
            if isinstance(v, Config):
                d[k] = v.full_dict
            else:
                d[k] = v
        return d

    def items(self):
        return self.dict.items()

    def get(self, key, default):
        return self.dict.get(key, default)

    def __contains__(self, key):
        return key in self.dict

    def __getitem__(self, key):
        return self.dict[key]

    def __getattr__(self, key):
        if key in self.dict:
            return self.dict[key]
        else:
            raise Exception("{} is not in config with fields {}".format(key, self.dict.keys()))

    def __setattr__(self, key, value):
        self.dict[key] = value

    def formatted(self, key, **kwargs):
        if isinstance(self.dict[key], str):
            st = self.dict[key]
            while '{' in st:
                try:
                    st = st.format(self.instance(), **kwargs)
                except Exception as e:
                    log_error("Error formatting:\n\t{}\nwith\n\t{}\nError: {}".format(st, kwargs, e))
                    raise
            return st
        return str(self.dict[key])

SSH_CMD = 'ssh -p {port} -i {key} {user}@{addr} "{cmd}"'
SCP_OUT_CMD = 'scp -P {port} -i {key} {src} {user}@{addr}:{dst}'
SCP_IN_CMD = 'scp -P {port} -i {key} -r {user}@{addr}:{src} {dst}'
RSYNC_IN_CMD = "rsync -av -e 'ssh -p {port} -i {key}' {user}@{addr}:{src} {dst}"

class Host:

    hosts_ = {}

    @classmethod
    def get(cls, host_name):
        return cls.hosts_[host_name]

    def __init__(self, host_name, host_cfg, index=0):
        log("Initializing {} to point to {}".format(host_name, host_cfg))

        self.index = None
        self.name = host_name
        self.addr = host_cfg.addr
        if 'ssh' in host_cfg:
            self.ssh = host_cfg.ssh
        else:
            self.ssh = Config.instance().ssh

        if host_name not in Host.hosts_:
            Host.hosts_[host_name] = {}

        Host.hosts_[host_name][index] = self

    def rsync_from(self, src, dst):
        cmd = RSYNC_IN_CMD.format(src=src, dst=dst, addr=self.addr, **self.ssh.dict)
        call(cmd, None, None)

    def execute(self, cmd, do_wait, enforce_duration, check_return):
        full_cmd = SSH_CMD.format(cmd=cmd, addr = self.addr, **self.ssh.dict)
        if not do_wait:
            log("Running {} in background on {}".format(cmd, self.name))
            thread = Thread(target=call, args = (full_cmd, enforce_duration, check_return))
            thread.daemon = True
            thread.start()
        else:
            log("Running {} in foreground on {}".format(cmd, self.name))
            return call(full_cmd, enforce_duration, check_return)


    @classmethod
    def init_hosts(cls, host_list):
        for name, hosts in host_list.items():
            if isinstance(hosts, list):
                for i, host in enumerate(hosts):
                    Host(name, host, i)
            else:
                Host(name, hosts)

class Log:

    logs_ = {}

    @classmethod
    def get(cls, name):
        if name in cls.logs_:
            return cls.logs_[name]
        return None

    @classmethod
    def has(cls, name):
        return name in cls.logs_

    def __init__(self, log_name, log_cfg):
        log("Initializing log {}".format(log_name))
        self.copied = defaultdict(lambda: False)
        self.cfg = log_cfg

        self.has_dir = 'dir' in log_cfg
        if 'logs' in Config.instance():
            self.log_dir = Config.instance().logs.dir
        elif 'log_dir' in Config.instance().programs:
            self.log_dir = Config.instance().programs.log_dir
        else:
            raise Exception("Cannot locate logs in cfg.logs.dir or cfg.programs.log_dir")

        self.dir = log_cfg.get('dir', '')
        self.full_dir = Config.format(os.path.join(self.log_dir, self.dir, ''))

        if 'log' in log_cfg:
            self.log_ = os.path.join(self.full_dir, log_cfg.log)
        else:
            self.log_ = None

        if 'out' in self.cfg:
            self.out = os.path.join(self.full_dir, self.cfg.out)
        else:
            self.out = None

        if 'err' in self.cfg:
            self.err = os.path.join(self.full_dir, self.cfg.err)
        else:
            self.err = None

        Log.logs_[log_name] = self

    def dict(self, **kwargs):
        if 'i' not in kwargs:
            kwargs['i'] = 0
        if 'host' not in kwargs:
            kwargs['host'] = '*HOST*'
        if self.log_ is not None:
            return dict(log=Config.format(self.log_, **kwargs))
        return dict()

    def suffix(self, **kwargs):
        suffix = ''
        if self.out is not None:
            suffix += ' > {}'.format(Config.format(self.out, **kwargs))
        if self.err is not None:
            suffix += ' 2> {}'.format(Config.format(self.err, **kwargs))
        return suffix

    def copy_local(self, hosts, dst_base, i_offset=0):
        threads = []
        for i, host in hosts.items():
            if self.has_dir:
                src = Config.format(self.full_dir, i=i+i_offset)
                dst = Config.format(os.path.join(dst_base, self.dir), i=i+i_offset, host=host.addr)
                # Have to make the directory manually, or else rsync might try to make it twice
                # and fail
                call("mkdir -p {}".format(dst), raise_error=True)

                thread = Thread(target=host.rsync_from, args=(src, dst))
                thread.start()
                threads.append(thread)
            else:
                for f in self.cfg.dict.values():
                    src = Config.format(os.path.join(self.full_dir, f), i=i+i_offset, host=host.addr)
                    thread = Thread(target=host.rsync_from, args=(src, dst_base))
                    thread.start()
                    threads.append(thread)
        for thread in threads:
            thread.join()
        self.copied[i_offset] = True

    @classmethod
    def init_logs(cls, log_list):
        for name, log in log_list.items():
            if name != 'dir':
                Log(name, log)

class Program:

    programs_ = {}

    @classmethod
    def get(cls, name):
        return cls.programs_[name]

    def __init__(self, name, program_cfg):
        self.name = name
        self.cfg = program_cfg
        log("Config is ", self.cfg)
        self.fg = self.cfg.get('fg', False)

        self.start = self.cfg.get('start', None)
        self.stop = self.cfg.get('stop', None)

        self.check_rtn = self.cfg.get('check_rtn', None)

        Program.programs_[name] = self

        try:
            self.hosts = Host.get(self.cfg.host)
        except:
            log_error("Error initiating host ", self.cfg.host, " for program ", name)
            raise

        self.init_i = self.cfg.get('init_i', 0)

        self.log = Log.get(name)
        if self.log is not None:
            print(name, "Log is", self.log.dict())

    def cmd(self, **kwargs):
        if self.log is not None:
            suffix = self.log.suffix(**kwargs)
            kwargs.update(self.log.dict(**kwargs))
        else:
            suffix = ''

        if self.start is not None:
            return '{} {}'.format(
                    Config.format(self.start, **kwargs),
                    suffix,
            )
        elif self.stop is not None:
            return self.stop_cmd(**kwargs)

    def stop_cmd(self, delay = None, **kwargs):
        if self.stop is None:
            return None
        if delay is not None:
            return 'sleep {} && {}'.format(
                    delay,
                    Config.format(self.stop, **kwargs)
            )
        return Config.format(self.stop, **kwargs)

    @classmethod
    def init_programs(self, program_list):
        for name, prog in program_list.items():
            try:
                Program(name, prog)
            except:
                log_error("Error initializing program ", name)
                raise

def safe_eval(st, label=''):
    try:
        return eval(st)
    except NameError as e:
        log_error("Error evaluating expression '{}' due to [{}]".format(label, e))
        raise


class Command:

    def __init__(self, program_name, cmd_cfg, index = None):
        self.cfg = cmd_cfg

        self.begin = 0
        self.duration = None

        if 'begin' in cmd_cfg:
            self.begin = float(safe_eval(cmd_cfg.formatted('begin'), 'begin'))

        self.index = index if index is not None else 0
        self.program = Program.get(program_name)

        self.log = Log.get(program_name)
        self.name = program_name

        if 'duration' in cmd_cfg:
            dur = safe_eval(cmd_cfg.formatted('duration', **self.dict()), 'duration')
            self.duration = float(dur)
            if self.program.start is None:
                log_fatal("{}: Cannot specify duration when program is missing 'start'".format(program_name))
        elif self.program.start is not None and self.program.stop is not None:
                log_fatal("{}: Must specify duration if program contains both 'start' and 'stop'".format(program_name))

        if 'enforce_duration' in cmd_cfg:
            if cmd_cfg.enforce_duration == True:
                if self.duration is None:
                    log_fatal("Specified enforce duration = True with no duration specified")
                self.enforced_duration = self.duration - 1
            else:
                self.enforced_duration = float(safe_eval(cmd_cfg.formatted('enforce_duration'), 'enforce_duration'))
        else:
            self.enforced_duration = None

    def dict(self, **kwargs):
        d = {}
        for k, v in self.cfg.items():
            d[k] = self.cfg.formatted(k, **kwargs)
        if self.log is not None:
            d.update(self.log.dict(**kwargs))
        d.update(begin=self.begin)
        if self.duration is not None:
            d.update(duration=self.duration)
        d.update(kwargs)
        return d

    def pretty(self, **kwargs):
        return self.name + " : " + pprint.pformat(self.dict(i=self.index, **kwargs))

    def run(self):
        log_info("Running command : {}".format(self.pretty()))

        starts = []
        stops = []

        for host_i, host in self.program.hosts.items():
            i = self.index + host_i + self.program.init_i

            cmd_kwargs = self.dict(i=i, host=host.addr)

            cmd = self.program.cmd(**cmd_kwargs)
            starts.append(cmd)
            host.execute(cmd, self.program.fg, self.enforced_duration, self.program.check_rtn)

            if self.program.stop is not None:
                stop_cmd = self.program.stop_cmd(self.duration, **cmd_kwargs)
                stops.append(stop_cmd)
                host.execute(stop_cmd, False, None, None)

        cmd_kwargs['name_'] = self.name
        cmd_kwargs['time_'] = float(time.time())
        if self.duration  is not None:
            cmd_kwargs['stop_time_'] = float(time.time() + self.duration)

        cmd_kwargs['starts_'] = starts
        cmd_kwargs['stops_'] = stops
        return cmd_kwargs

    def stop(self):
        log("Stopping command : {}".format(self.pretty()))

        for host_i, host in self.program.hosts.items():
            i = self.index + host_i + self.program.init_i

            cmd_kwargs = copy.deepcopy(self.dict(i=i))

            cmd = self.program.stop_cmd(**cmd_kwargs)

            if cmd is not None:
                host.execute(cmd, True, None, None)

        cmd_kwargs['name_'] = self.name
        cmd_kwargs['stop_time_'] = float(time.time())

        return cmd_kwargs


#https://stackoverflow.com/questions/528281/how-can-i-include-an-yaml-file-inside-another
class Loader(yaml.SafeLoader):

    def __init__(self, stream):

        self._root = os.path.split(stream.name)[0]

        super(Loader, self).__init__(stream)

    def include(self, node):

        filename = os.path.join(self._root, self.construct_scalar(node))

        with open(filename, 'r') as f:
            rtn = yaml.load(f, Loader)
            TestRunner.instance().included_files.append(filename)
            return rtn

Loader.add_constructor('!include', Loader.include)


class TestRunner:

    instance_ = None

    @classmethod
    def instance(cls):
        return cls.instance_

    def open_log(self):
        global LOGFILE
        LOGFILE = open(os.path.join(self.output_dir, 'shremote.log'), 'w')

    def close_log(self):
        LOGFILE.close()

    def __init__(self, cfg_file, label, out_dir, export_loc, test_run, args_dict):
        if TestRunner.instance_ is None:
            TestRunner.instance_ = self
        else:
            log_fatal("Cannot instantiate multiple TestRunners")
        self.initialized = False

        self.output_dir = os.path.join(out_dir, label) + '/'

        self.included_files = []

        self.test_run = test_run

        self.cfg_file = cfg_file
        with open(cfg_file, 'r') as f:
            self.raw_cfg = yaml.load(f, Loader)

        call("mkdir -p %s" % self.output_dir, raise_error=True)
        self.cfg = Config(self.raw_cfg, label=label, args=args_dict, out=self.output_dir)
        self.open_log()
        log("Initialized cfg at {}, label {}".format(cfg_file, label))

        self.event_log = []
        if export_loc is not None:
            self.export_dir = os.path.join(export_loc, label)
            self.do_export = True
        else:
            self.do_export = False

        Host.init_hosts(self.cfg.hosts)

        if 'log' in self.cfg:
            Log.init_logs(self.cfg.logs)
        else:
            for name, prog in self.cfg.programs.items():
                if name != 'log_dir':
                    if 'log' in prog:
                        Log(name, prog.log)

        self.programs = {}
        for name, prog in self.cfg.programs.items():
            if name == 'log_dir':
                continue
            try:
                self.programs[name] = Program(name, prog)
            except:
                log_error("Error initializing program ", name)
                raise

        self.commands = []
        for name, cmd_group in self.cfg.commands.dict.items():
            if isinstance(cmd_group, list):
                for i, cmd in enumerate(cmd_group):
                    self.commands.append(Command(name, cmd, index=i))
            else:
                self.commands.append(Command(name, cmd_group))
        self.initialized = True


    @property
    def sorted_commands(self):
        return sorted(self.commands, key = lambda c: c.begin)

    def export_logs(self):
        log("Exporting logs...")
        shutil.copytree(self.output_dir, self.export_dir)

    def run_init_cmds(self):
        for cmd, _ in self.cfg.init_cmds.items():
            cmd = self.cfg.init_cmds.formatted(cmd)
            cmd = cmd.replace('\n', ' ')
            call(cmd, raise_error=True)

    def copy_files(self):
        for name, file in self.cfg.files.dict.items():
            src = file.formatted('src')
            dst = file.formatted('dst')
            dir = os.path.dirname(dst)

            if 'host' in file:
                file_hosts = [file.host]
            elif 'hosts' in file:
                file_hosts = file.hosts
            else:
                log_fatal("File {} does not specify host or hosts".format(name))

            for host_name in file_hosts:
                hosts = Host.get(host_name)
                for host in hosts.values():
                    ssh = host.ssh
                    addr = host.addr

                    ssh_cmd = SSH_CMD.format(cmd = 'mkdir -p %s' % dir,
                                             addr=addr, **ssh.dict)
                    call(ssh_cmd, check_return=0, raise_error=True)

                    cmd = SCP_OUT_CMD.format(src=src, dst=dst, addr=addr, **ssh.dict)
                    call(cmd, check_return=0)

    def mkdirs(self):
        threads = []
        for cmd in self.commands:
            prog = cmd.program
            hosts = prog.hosts
            for i, host in hosts.items():
                if prog.log is None:
                    continue
                dir = prog.log.full_dir.format(i=i)
                ssh = host.ssh

                cmd = SSH_CMD.format(cmd = 'mkdir -p %s' % dir, addr = host.addr, **ssh.dict)
                thread = Thread(target=call, args=(cmd,), kwargs=dict(check_return=0, raise_error=True))
                thread.start()
                threads.append(thread)
        for thread in threads:
            thread.join()

    def show_commands(self):
        log("*****  List of commands to run: ")
        for command in self.sorted_commands:
            log(command.pretty())

    def run_commands(self):
        min_begin = min(c.begin for c in self.commands)
        start_time = time.time() - min_begin

        elapsed = 0
        last_begin = 0
        for command in self.sorted_commands:
            elapsed = time.time() - start_time
            delay = command.begin - elapsed

            if (delay > 0):
                log("Sleeping for %d" % delay)
                if not self.test_run:
                    if error_event.wait(delay):
                        log_fatal("Error encountered in other thread!")
                else:
                    time.sleep(.1)
            elif last_begin != command.begin and delay > .001:
                log_warn("Falling behind on command execution by %.1f " % delay)

            last_begin = command.begin
            try:
                self.event_log.append(command.run())
            except Exception:
                traceback.print_exc()
                log_fatal("Error attempting to run command ", command.pretty())

        try:
            max_end = max(c.begin + c.duration for c in self.commands if c.duration is not None)
            elapsed = time.time() - start_time
            delay = max_end - elapsed
            if not self.test_run:
                if error_event.wait(delay):
                    log_fatal("Error encountered in other thread!")
        except Exception:
            pass

    def stop_all(self):
        for command in self.sorted_commands:
            self.event_log.append(command.stop())

    def get_logs(self):
        call("mkdir -p %s" % self.output_dir, raise_error=True)

        logs = set()
        for command in self.commands:
            program = command.program
            if program.log is not None:
                if not program.log.copied[command.index]:
                    program.log.copy_local(program.hosts, self.output_dir, command.index)

        call('cp {} {}/'.format(self.cfg_file, self.output_dir), raise_error=True)
        call('cp {} {}/shremote_cfg.yml'.format(self.cfg_file, self.output_dir), raise_error=True)

        for filename in self.included_files:
            call('cp {} {}/'.format(filename, self.output_dir), raise_error=True)

    def write_log(self):
        output = open(os.path.join(self.output_dir, 'event_log.json'), 'w')
        json.dump(self.event_log, output, indent=2)

    def run(self):
        if self.do_export:
            if self.test_run:
                self.export_dir += '__TEST'
            if os.path.exists(self.export_dir):
                log_warn("Export directory {} already exists! " \
                         "Will NOT export at end of test".format(self.export_dir))
                self.do_export = False
                time.sleep(2)
            else:
                log("Exporting to {} at end of test".format(self.export_dir))
                time.sleep(1)

        self.mkdirs()
        self.run_init_cmds()
        self.copy_files()
        self.show_commands()
        self.run_commands()

        self.get_logs()
        self.write_log()

        if self.do_export:
            self.export_logs()
        else:
            log("Skipping log export")

        log("Done with test!")

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Run remote commands')
    parser.add_argument('cfg_file', type=str, help='.yml cfg file')
    parser.add_argument('label', type=str, help='Label for resulting logs and sql dump')
    parser.add_argument('--test', action='store_true', help='run through each command quickly')
    parser.add_argument('--export', type=str, required=False, help='Location to place files')
    parser.add_argument('--get-only', action='store_true', help='only retrieve files')
    parser.add_argument('--stop-only', action='store_true', help='run only stop commands')
    parser.add_argument('--out', type=str, default=".", help=('output directory'))
    parser.add_argument('--args', type=str, required=False,
                        help='additional arguments for yml (format k1:v1;k2:v2')

    args = parser.parse_args()

    if args.test:
        test_mode = True

    args_dict = {}
    if args.args is not None:
        entries = args.args.split(';')
        for entry in entries:
            k, v = entry.split(':')
            args_dict[k] = v
            log("Adding arg: {} = {}", k, v)

    tester = TestRunner(args.cfg_file, args.label, args.out, args.export, args.test, args_dict)

    if args.stop_only:
        tester.stop_all()
    elif args.get_only:
        tester.get_logs()
    else:
        tester.run()

    tester.close_log()
