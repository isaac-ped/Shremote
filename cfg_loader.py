import yaml
import os
import re
import copy
import pprint
from collections import defaultdict
from include_loader import IncludeLoader
from fmt_config import CfgFormatException, FmtConfig

class CfgFormatFileException(Exception):
    pass

def wrong_type_exception(name, type, expected):
    return CfgFormatFileException(
            "Element {} is type {}. Expected: {}".format(name, type, expected)
    )

def verifier(fn):
    def inner(self, elem, name):
        self._names[name] = elem
        return fn(self, elem, name)
    return inner

class CfgLoader(object):

    TYPES = {'bool': bool,
                'int': int,
                'float': float,
                'str': str,
                'defaultdict': lambda: defaultdict(str),
                None: lambda: None}

    FLAGS = ('required', 'list_ok', 'formattable')

    def __init__(self, format):
        self.format = format
        self._names = {}
        self._verify_fmt_format(format, '')
        self._check_unused_fmt_fields(format, '')

    def load_cfg(self, raw_cfg):
        cfg = FmtConfig(raw_cfg)
        self._expand_cfg_format(cfg, [], self.format, None, True)
        cfg.enable_computed_fields()
        for child in cfg.children(recursive=True):
            try:
                if child.is_leaf():
                    child.format()
            except ValueError as e:
                raise CfgFormatException(
                        "Error casting config entry {} to one of {}: {}"
                        .format(child.get_name(), child.get_types(),  e)
                )
            except KeyError as e:
                raise CfgFormatException(
                        "Error formatting config entry {}: {}"
                        .format(child.get_name(), e)
                )
        cfg.disable_computed_fields()
        return cfg

    def _get_reference_fmt(self, referent_path):
        reference_fmt = self.format
        for keyname in referent_path:
            for field in reference_fmt['fields']:
                if field['key'] == keyname:
                    reference_fmt = field['format']
                    break
            else:
                raise CfgFormatFileException(
                        "Reference format {} does not exist in cfg format file"
                        .format(fmt_referent_name)
                      )
        return reference_fmt

    def _expand_cfg_map(self, cfg, field_path, fmt, exists):
        if 'fields' in fmt:
            for field in fmt['fields']:
                self._expand_cfg_field(cfg, field_path, field, fmt, exists)
        if 'format' in fmt:
            if cfg.haspath(field_path):
                sub_fmt = fmt['format']
                for cfg_field in cfg.getpath(field_path):
                    self._expand_cfg_format(cfg, field_path + [cfg_field], sub_fmt, fmt, exists)
        if 'computed_fields' in fmt:
            if cfg.haspath(field_path):
                cfg_entry = cfg.getpath(field_path)
                for field in fmt['computed_fields']:
                    cfg_entry.add_computed_field(field['key'], self.TYPES[field['format']['type']])
        if 'flags' in fmt and 'formattable' in fmt['flags']:
            if cfg.haspath(field_path):
                cfg.getpath(field_path).set_formattable()


    def _expand_cfg_primitive(self, cfg, field_path, fmt, exists):
        if cfg.haspath(field_path):
            types = fmt['type'] if isinstance(fmt['type'], list) else [fmt['type']]
            for type_ in types:
                cfg_entry = cfg.getpath(field_path)
                cfg_entry.allow_type(self.TYPES[type_])

    def _expand_cfg_list(self, cfg, field_path, fmt, exists):
        if cfg.haspath(field_path):
            sub_fmt = fmt['format']
            for i in range(len(cfg.getpath(field_path))):
                self._expand_cfg_format(cfg, field_path + [i], sub_fmt, fmt, exists)

    def _expand_cfg_reference(self, cfg, field_path, fmt, exists):
        referent_path = fmt['referent']
        if cfg.haspath(field_path) and cfg.getpath(field_path).is_leaf():
            cfg_entry = cfg.getpath(field_path)
            ref_path = referent_path + [cfg_entry.format()]
            if not cfg.haspath(ref_path):
                raise CfgFormatException(
                        "Path {} does not exist in config"
                        .format(ref_path))
            referent = cfg.getpath(ref_path)
            cfg.setpath(field_path, referent)
        elif cfg.haspath(field_path):
            reference_fmt = self._get_reference_fmt(referent_path)
            if reference_fmt['type'] != 'map' or 'format' not in reference_fmt:
                raise CfgFormatFileException(
                        "Reference format {} is not an unspecified map type"
                        .format(referent_path))
            reference_fmt = reference_fmt['format']
            exists = exists and cfg.haspath(field_path)
            self._expand_cfg_format(cfg, field_path, reference_fmt, None, exists)

    def _expand_cfg_inherit(self, cfg, field_path, fmt, parent_fmt, exists):
        if cfg.haspath(field_path):
            inherited_field = None
            inherited_fmt = parent_fmt
            for inherited_field_name in fmt['parent']:
                for field in inherited_fmt['fields']:
                    if field['key'] == inherited_field_name:
                        inherited_field = field
                        inherited_fmt = field['format']
                        if inherited_fmt['type'] == 'reference':
                            inherited_field = self._get_reference_fmt(inherited_fmt['referent'])
                            inherited_fmt = inherited_field['format']
                        break
                else:
                    raise CfgFormatFileException(
                            "Parent format {} does not exist in {}"
                            .format(inherited_field_name, inherited_field))
            self._expand_cfg_field(cfg, field_path[:-1], inherited_field, None, True)
        else:
            parent_path = field_path[:-1] + fmt['parent']
            if not cfg.haspath(parent_path):
                raise CfgFormatException(
                        "Config lacks paths {} and {}"
                        .format(field_path, parent_path))
            cfg.setpath(field_path, cfg.getpath(parent_path))

    def _expand_cfg_override(self, cfg, field_path, fmt, parent_fmt, exists):
        override = fmt['overrides']
        if not cfg.haspath(field_path):
            if not cfg.haspath(override):
                raise CfgFormatException(
                        "Config lacks paths {} and {}"
                        .format(field_path, override))
            cfg.setpath(field_path, cfg.getpath(override))
        else:
            reference_fmt = self._get_reference_fmt(override)
            if reference_fmt['type'] != 'map' or 'fields' not in reference_fmt:
                raise CfgFormatFileException("Reference format {} is not specified map type"
                                             .format(override))
            self._expand_cfg_format(cfg, field_path, reference_fmt, parent_fmt, True)


    def _expand_cfg_format(self, cfg, field_path, fmt, parent_fmt, exists):
        if isinstance(fmt['type'], list) or fmt['type'] in self.TYPES:
            self._expand_cfg_primitive(cfg, field_path, fmt, exists)
        elif fmt['type'] == 'map':
            self._expand_cfg_map(cfg, field_path, fmt, exists)
        elif fmt['type'] == 'list':
            self._expand_cfg_list(cfg, field_path, fmt, exists)
        elif fmt['type'] == 'reference':
            self._expand_cfg_reference(cfg, field_path, fmt, exists)
        elif fmt['type'] == 'inherit':
            self._expand_cfg_inherit(cfg, field_path, fmt, parent_fmt, exists)
        elif fmt['type'] == 'override':
            self._expand_cfg_override(cfg, field_path, fmt, parent_fmt, exists)
        else:
            raise Exception("HOW DID YOU DO THIS")

    def _expand_cfg_field(self, cfg, field_path, field, parent_fmt, exists):
        field_required = 'required' in field['flags']
        list_ok = 'list_ok' in field['flags']
        key = field['key']
        keypath = field_path + [key]

        if not cfg.haspath(keypath) and field['default'] is not None:
            cfg.setpath(keypath, field['default'])

        if cfg.haspath(keypath) and list_ok:
            raw_cfg = cfg.getpath(keypath).get_raw()
            if not isinstance(raw_cfg, list):
                cfg.setpath(keypath, [raw_cfg])
            if not field['format']['type'] == 'list':
                list_fmt = {'type': 'list', 'format': field['format']}
                field['format'] = list_fmt

        self._expand_cfg_format(cfg, keypath, field['format'], parent_fmt, exists)

        if exists and field_required and not cfg.haspath(keypath):
            raise CfgFormatException("Required field {} does not exist in config".format(keypath))


    def _check_unused_fmt_fields(self, format, name):
        if name not in self._names:
            raise CfgFormatFileException("Unused field: %s" % name)
        if isinstance(format, list):
            for i, elem in enumerate(format):
                ename = name + '[%d]' % i
                self._check_unused_fmt_fields(elem, ename)
        elif isinstance(format, dict):
            for k, elem in format.items():
                vname = name + '.' + k
                self._check_unused_fmt_fields(elem, vname)

    def _verify_fmt(self, elem, name, key, type_=None, optional=False):
        if optional and key not in elem:
            if type_ is not None:
                elem[key] = type_()
            else:
                elem[key] = None
        sub, sname = self._get_fmt(elem, name, key)
        if type_ is not None and not isinstance(elem[key], type_):
            raise wrong_type_exception(sname, type(elem[key]), type_)
        if isinstance(sub, list):
            for i, _ in enumerate(sub):
                self._names[sname + '[%d]' % i] = sub

    def _get_fmt(self, elem, name, key):
        subname = name + '.' + key
        if key not in elem:
            raise CfgFormatFileException("Element {} lacks '{}'".format(name, key))
        self._names[subname] = elem[key]
        return elem[key], subname

    def _verify_fmt_list(self, elem, name, verifier):
        if not isinstance(elem, list):
            raise wrong_type_exception(name, type(elem), list)
        for i, lelem in enumerate(elem):
            verifier(lelem, name + '[%d]' % i)

    @verifier
    def _verify_fmt_map_type(self, elem, name):
        if 'fields' in elem:
            fields, fname = self._get_fmt(elem, name, 'fields')
            self._verify_fmt_fields(fields, fname)
        if 'format' in elem:
            fmt, fname = self._get_fmt(elem, name,  'format')
            self._verify_fmt_format(fmt, fname)
        if 'computed_fields' in elem:
            fields, fname = self._get_fmt(elem, name, 'computed_fields')
            self._verify_fmt_fields(fields, fname)
        if 'flags' in elem:
            flags, fname = self._get_fmt(elem, name, 'flags')
            self._verify_flags(flags, fname)

    @verifier
    def _verify_fmt_list_type(self, elem, name):
        fmts, fname = self._get_fmt(elem, name, 'format')
        self._verify_fmt_format(fmts, fname)

    @verifier
    def _verify_fmt_reference_type(self, elem, name):
        self._verify_fmt(elem, name, 'referent', list)

    @verifier
    def _verify_fmt_inherit_type(self, elem, name):
        self._verify_fmt(elem, name, 'parent', list)

    @verifier
    def _verify_fmt_override_type(self, elem, name):
        self._verify_fmt(elem, name, 'overrides', list)

    @verifier
    def _verify_fmt_format(self, elem, name):
        etype, tname = self._get_fmt(elem, name, 'type')
        if isinstance(etype, list):
            self._verify_fmt(elem, name, 'type', list)
            if not all([et in self.TYPES for et in etype]):
                raise CfgFormatFileException("For reference element {}: not all types are basic".format(name))
            return

        if etype == 'map':
            self._verify_fmt_map_type(elem, name)
        elif etype == 'list':
            self._verify_fmt_list_type(elem, name)
        elif etype == 'reference':
            self._verify_fmt_reference_type(elem, name)
        elif etype == 'inherit':
            self._verify_fmt_inherit_type(elem, name)
        elif etype == 'override':
            self._verify_fmt_override_type(elem, name)
        elif etype not in self.TYPES:
            raise CfgFormatFileException("Unknown type {} for {}".format(etype, tname))

    @verifier
    def _verify_flags(self, elem, name):
        for i, flag in enumerate(elem):
            self._names[name + '[%d]' % i] = elem
            if not (flag in self.FLAGS):
                raise CfgFormatFileException("Unknown flag in {}: {}".format(name, flag))


    @verifier
    def _verify_fmt_field_item(self, elem, name):
        self._verify_fmt(elem, name, 'key', str)
        fmts, fname = self._get_fmt(elem, name, 'format')
        self._verify_fmt_format(fmts, fname)
        self._verify_fmt(elem, name, 'aliases', list, optional=True)
        self._verify_fmt(elem, name, 'default', optional=True)
        if 'flags' in elem:
            flags, fname = self._get_fmt(elem, name, 'flags')
            self._verify_flags(flags, fname)
        self._verify_fmt(elem, name, 'flags', list, optional=True)

    @verifier
    def _verify_fmt_fields(self, elem, name):
        self._verify_fmt_list(elem, name, self._verify_fmt_field_item)

DEFAULT_CFG_FMT_FILE = os.path.join(os.path.dirname(__file__), 'cfg_format.yml')


def load_cfg_file(cfg_filename, loader_filename = None):
    if loader_filename is None:
        loader_filename = DEFAULT_CFG_FMT_FILE
    with open(loader_filename, 'r') as f:
        loader = CfgLoader(yaml.load(f, yaml.SafeLoader))

    with open(cfg_filename, 'r') as f:
        raw_cfg = yaml.load(f, IncludeLoader)

    return loader.load_cfg(raw_cfg)

if __name__ == '__main__':
    cfg = load_cfg_file('test/sample_cfgs/simple_cfg.yml')

    print(cfg.pformat())
    for cmd in cfg.commands:
        start = cmd.program.start.format(i=0)
        begin = cmd.begin[0].format()
        print("Comnand '{}'\n\tstarts at time {}".format(start, begin))
