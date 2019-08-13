import yaml
from collections import defaultdict
from fmt_config import FmtConfig, CfgFormatException

class CfgMetaFormatException(Exception):
    pass

def NullType(x):
    if x is None or x == 0:
        return None

class CfgField(object):

    NoDefault = object()
    _cfg_instance = None

    def __init__(self, key, types=None,
                 default = NoDefault, required = False,
                 list_ok = False, aliases = None, inherit=None):
        self.key = key
        if not isinstance(types, list):
            self.types = [types]
        else:
            self.types = types
        self.default = default
        self.required = required
        if aliases is not None and not isinstance(aliases, list):
            self.aliases = [aliases]
        else:
            self.aliases = aliases
        self.inherit = inherit
        self.list_ok = list_ok
        self.pre_formatted = set()

    @classmethod
    def set_cfg(cls, cfg):
        cls._cfg_instance = cfg

    @classmethod
    def cfg(cls):
        return cls._cfg_instance

    def _check_required(self, parent_cfg):
        if not self.key in parent_cfg  and self.required:
            raise CfgFormatException("Cfg element {} does not have requied field {}"
                    .format(parent_cfg.get_name(), self.key))

    def _check_aliases(self, parent_cfg):
        if self.key in parent_cfg:
            return
        if self.aliases is not None:
            for alias in self.aliases:
                if alias in parent_cfg:
                    parent_cfg[self.key] = parent_cfg[alias]
                    return

    def _set_default(self, parent_cfg):
        if self.key not in parent_cfg and self.default != self.NoDefault:
            parent_cfg[self.key] = self.default

    def _do_inherit(self, parent_cfg):
        if self.inherit is not None and self.inherit.cfg() is not None:
            if not self.list_ok:
                parent_cfg.mergepath([self.key], self.inherit.cfg())
            elif self.key not in parent_cfg:
                parent_cfg[self.key] = self.inherit.cfg()

    def _set_types(self, cfg):
        if self.types is not None:
            for _type in self.types:
                cfg.allow_type(_type)

    def _listify(self, parent_cfg):
        if self.key in parent_cfg and self.list_ok and not parent_cfg[self.key].is_list():
            parent_cfg[self.key] = [parent_cfg[self.key]]

    def pre_format(self, parent_cfg):
        self._check_aliases(parent_cfg)
        self._set_default(parent_cfg)
        self._do_inherit(parent_cfg)
        self._check_required(parent_cfg)
        self._listify(parent_cfg)
        if self.key in parent_cfg:
            self.set_cfg(parent_cfg[self.key])
        return self.key in parent_cfg

    def format(self, cfg):
        if self.list_ok and cfg.is_list():
            for subcfg in cfg:
                if not subcfg.is_list():
                    self.format(subcfg)
        else:
            self._format(cfg)

    def _format(self, cfg):
        self.set_cfg(cfg)
        self._set_types(cfg)
        return cfg

class CfgMap(CfgField):
    _fields = []
    _computed_fields = []

    @classmethod
    def get_field(cls, key):
        for field in cls._fields:
            if field.key == key:
                return field
        raise CfgMetaFormatException("Key {} does not exist in {}".format(key, cls))

    def __init__(self, key, format_root=False, *args, **kwargs):
        super(CfgMap, self).__init__(key, None, *args, **kwargs)
        self.format_root = format_root

    def pre_format_children(self, cfg):
        for field in self._fields:
            field.pre_format(cfg)

    def pre_format(self, parent_cfg):
        pre_formatted = super(CfgMap, self).pre_format(parent_cfg)
        if not pre_formatted:
            # initiailze if children have defaults
            for field in self._fields:
                if field.default != self.NoDefault:
                    parent_cfg[self.key] = {}
                    break

        if pre_formatted or super(CfgMap, self).pre_format(parent_cfg):
            self.pre_format_children(parent_cfg[self.key])
            return True
        return False

    def _format(self, cfg):
        for field in self._fields:
            if field.key in cfg:
                subfield = cfg[field.key]
                field.format(subfield)

        for field in self._computed_fields:
            field.default = field.types[0]()
            field.pre_format(cfg)
            cfg[field.key].set_computed()

        if self.format_root:
            cfg.set_formattable()

class CfgMapList(CfgMap):

    def pre_format(self, parent_cfg):
        if self.key not in parent_cfg:
            return False
        for subcfg in parent_cfg[self.key]:
            self.pre_format_children(subcfg)

    def _format(self, cfg):
        for cfg_item in cfg:
            super(CfgMapList, self)._format(cfg_item)

class CfgMapMap(CfgMap):
    def __init__(self, key, *args, **kwargs):
        super(CfgMapMap, self).__init__(key, *args, **kwargs)
        references = {}

    def refer(self, key):
        return self.cfg()[key]

    def pre_format(self, parent_cfg):
        if self.key not in parent_cfg:
            return False
        for subcfg in parent_cfg[self.key].values():
            self.pre_format_children(subcfg)

    def format_value(self, value):
        super(CfgMapMap, self)._format(value)

    def _format(self, cfg):
        self.set_cfg(cfg)
        for key, value in cfg.items():
            if 'name' not in value:
                value.name = key
            self.format_value(value)

class CfgReference(CfgMap):
    def __init__(self, key, Referent, *args, **kwargs):
        super(CfgReference, self).__init__(key, *args, **kwargs)
        self.referent = Referent(key, *args, **kwargs)

    def get_field(self, key):
        return self.referent.get_field(key)

    def pre_format(self, parent_cfg):
        if self.key not in parent_cfg:
            self._do_inherit(parent_cfg)
        return super(CfgReference, self).pre_format(parent_cfg)

    def _format(self, cfg):
        self.set_cfg(cfg)
        if cfg.is_leaf():
            cfg.set_value(self.referent.refer(cfg.format()))
        elif 'name' not in cfg:
            cfg['name'] = '_anonymous'

        self.referent.format_value(cfg)


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
            CfgField('checked_rtn', [int, NullType], None, aliases=('check_rtn'))
    ]

class HostsCfg(CfgMapMap):
    _fields = [
            CfgField('hostname', str, required=True, aliases=('addr')),
            CfgMap('ssh', inherit=SshCfg),
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
            CfgField('stop', str, default=None),
            ProgramLogCfg('log'),
            CfgField('duration_reduced_error', bool, default=True),
            CfgField('duration_exceeded_error', bool, default=False),
            CfgField('bg', bool, default=False),
            CfgMap('defaults')
    ]

class CommandsCfg(CfgMapList):
    Program = CfgReference('program', ProgramsCfg, required=True)

    _fields = [
            Program,
            CfgReference('hosts', HostsCfg, inherit=Program.get_field('hosts'), list_ok = True),
            CfgField('begin', float, required=True),
            CfgField('min_duration', [float, NullType], default=None),
            CfgField('max_duration', [float, NullType], default=None),
    ]

    _computed_fields = [
            CfgField('host_idx', int),
            CfgField('log_dir', str),
            CfgField('host', lambda : defaultdict(str)),
    ]

class CfgFmt(CfgMap):
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

    def __init__(self):
        super(CfgFmt, self).__init__('')

    def format_cfg(self, cfg):
        self.pre_format_children(cfg)
        self.format(cfg)
        cfg.disable_computed_fields()

def load_cfg(cfg, fmt = CfgFmt()):
    if isinstance(cfg, str):
        with open(cfg, 'r') as f:
            cfg = yaml.load(f)
    cfg = FmtConfig(cfg)
    fmt.format_cfg(cfg)
    return cfg

if __name__ == '__main__':
    import sys
    cfg = load_cfg(sys.argv[1])
    for cmd in cfg.commands:
        start = cmd.program.start.format(host_idx=0, host = cmd.hosts[0])
        begin = cmd.begin.format()
        print("Command '{}'\n\tstarts at time {}".format(start, begin))
