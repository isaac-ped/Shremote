import yaml
from collections import defaultdict
from cfg_formatter import CfgField, CfgMap, CfgMapList, CfgMapMap, CfgReference, NullType, TopLvlCfg
from fmt_config import FmtConfig
from include_loader import IncludeLoader

class LogDirCfg(CfgField):
    def __init__(self, key, *args, **kwargs):
        super(LogDirCfg, self).__init__(key, str, '~/shremote_logs', *args, **kwargs)

class SshCfg(CfgMap):
    _fields = [
            CfgField('user', str, '{0.user}'),
            CfgField('key', str, '~/.ssh/id_rsa'),
            CfgField('port', int, 22)
    ]

class CmdsCfg(CfgMapList):
    _fields = [
            CfgField('cmd', str, required=True),
            CfgField('checked_rtn', [int, bool], default=0, aliases=('check_rtn')),
    ]

class HostsCfg(CfgMapMap):
    _fields = [
            CfgField('hostname', str, required=True, aliases=('addr'), list_ok=True),
            CfgMap('ssh', inherit=SshCfg),
            CfgField('log_dir', inherit=LogDirCfg)
    ]

class FilesCfg(CfgMapMap):
    _fields = [
            CfgField('src', str, required=True),
            CfgField('dst', str, required=True),
            CfgReference('hosts', HostsCfg, list_ok = True, required=True, aliases=('host'))
    ]
    _computed_fields = [
            CfgField('out_dir', str)
    ]

class ProgramLogCfg(CfgMap):
    _fields = [
            CfgField('dir', str, default=''),
            CfgField('out', str),
            CfgField('err', str),
    ]


class ProgramsCfg(CfgMapMap):
    _fields = [
            CfgReference('hosts', HostsCfg, list_ok = True, aliases=('host')),
            CfgField('start', str, required=True),
            CfgField('stop', str, default=None),
            # TODO: Add 'kill' field
            ProgramLogCfg('log'),
            CfgField('duration_reduced_error', bool, default=True),
            CfgField('duration_exceeded_error', bool, default=False),
            CfgField('bg', bool, default=False),
            CfgField('checked_rtn', [int, bool], default=False, aliases=('check_rtn')),
            CfgField('defaults', dict, default=dict())
    ]

class CommandsCfg(CfgMapList):

    _fields = [
            CfgReference('program', ProgramsCfg, required=True),
            CfgReference('hosts', HostsCfg, sibling_inherit=['program', 'hosts'], list_ok = True),
            CfgField('begin', float, required=True),
            CfgField('min_duration', [float, NullType], default=None),
            CfgField('max_duration', [float, NullType], default=None),
    ]

    _computed_fields = [
            CfgField('host_idx', int),
            CfgField('log_dir', str),
            CfgField('host', lambda : defaultdict(str)),
    ]

    _child_inherit = ['program', 'defaults']

class CfgFmt(TopLvlCfg):
    _fields = [
            LogDirCfg('log_dir'),
            SshCfg('ssh'),
            CmdsCfg('init_cmds', format_root=True),
            CmdsCfg('post_cmds', format_root=True),
            HostsCfg('hosts'),
            FilesCfg('files', format_root=True),
            ProgramsCfg('programs'),
            CommandsCfg('commands', format_root=True)
    ]

    _computed_fields = [
            CfgField('user', str),
            CfgField('label', str),
            CfgField('args', defaultdict),
            CfgField('cfg_dir', str)
    ]

def load_cfg(cfg, fmt = CfgFmt()):
    if isinstance(cfg, str):
        with open(cfg, 'r') as f:
            cfg = yaml.load(f, Loader=IncludeLoader)
    cfg = FmtConfig(cfg)
    fmt.format(cfg)
    return cfg

if __name__ == '__main__':
    import sys
    cfg = load_cfg(sys.argv[1])
    for cmd in cfg.commands:
        start = cmd.program.start.format(host_idx=0, host = cmd.hosts[0])
        begin = cmd.begin.format()
        print("Command '{}'\n\tstarts at time {}".format(start, begin))
