
class CfgEntity(object):
    NullType = lambda : None

class CfgField(CfgEntity):
    NO_DEFAULT = object()
    FIXED_MAP = object()

    def __init__(self, key, types=None, 
                 default = NO_DEFAULT, required = False, 
                 list_ok = False, aliases = None, inherit=None):
        self.key = key
        self.types = types
        self.default = default
        self.required = required
        self.aliases = aliases
        self.inherit = inherit

class CfgMap(CfgField):
    _fields = []

    @classmethod
    def field(cls, key):
        pass

    def __init__(self, key, *args, **kwargs):
        super(CfgMap, self).__init__(key, self.FIXED_MAP, *args, **kwargs)

class CfgMapList(CfgMap):
    pass

class CfgMapMap(CfgMap):
    pass

class CfgReference(CfgMap):
    def __init__(self, key, Referent, *args, **kwargs):
        super(CfgReference, self).__init__(key, *args, **kwargs)
        self.Referent = Referent

class LogDirCfg(CfgField):
    def __init__(self, key, *args, **kwargs):
        super(LogDirCfg, self).__init__(key, str, '~/shremote_logs', *args, **kwargs)

class SshCfg(CfgMap):
    _fields = (
            CfgField('user', str, '{0.user}'),
            CfgField('key', str, '~/.ssh/id_rsa'),
            CfgField('port', int, 22)
    )

class CmdsCfg(CfgMapList):
    _fields = [
            CfgField('cmd', str, required=True),
            CfgField('checked_rtn', [int, NullType], None, aliases=('check_rtn'))
    ]

class HostsCfg(CfgMapMap):
    _fields = [
            CfgField('hostname', str, required=True, aliases=('addr')),
            CfgReference('ssh', SshCfg),
            CfgField('log_dir', inherit=LogDirCfg)
    ]

class FilesCfg(CfgMapMap):
    _fields = [
            CfgField('src', str, required=True),
            CfgField('dst', str, required=True),
            CfgReference('hosts', HostsCfg, list_ok = True, required=True)
    ]
    _computed_fields = [
            CfgField('out_dir', str)
    ]

class ProgramLogCfg(CfgMap):
    _fields = [
            CfgField('dir', str, default=''),
            CfgField('out', str),
            CfgField('err', str)
    ]


class ProgramsCfg(CfgMapMap):
    _fields = [
            CfgReference('hosts', HostsCfg, list_ok = True),
            CfgField('start', str, required=True),
            CfgField('stop', str, default=NullType),
            ProgramLogCfg('log'),
            CfgField('duration_reduced_error', bool, default=True),
            CfgField('duration_exceeded_error', bool, default=False),
            CfgField('bg', bool, default=False),
            CfgMap('defaults')
    ]

class CommandsCfg(CfgMapList):
    _fields = [
            CfgReference('program', ProgramsCfg, required=True),
            HostsCfg('hosts', inherit = ProgramsCfg.field('hosts'), list_ok=True),
            CfgField('begin', float, required=True),
            CfgField('min_duration', [float, NullType], default=None),
            CfgField('max_duration', [float, NullType], default=None),
    ]

    _computed_fields = [
            CfgField('host_idx', int),
            CfgField('log_dir', str),
            HostsCfg('host', list_ok = False),
    ]

class CfgFmt(CfgMap):
    _fields = [
            LogDirCfg('log_dir'),
            SshCfg('ssh'),
            CmdsCfg('init_cmds'),
            CmdsCfg('post_cmds'),
            HostsCfg('hosts'),
            FilesCfg('files'),
            ProgramsCfg('programs'),
            CommandsCfg('commands')
    ]

    _computed_fields = [
            CfgField('user', str),
            CfgField('label', str),
            CfgField('args', defaultdict),
            CfgField('cfg_dir', str)
    ]
