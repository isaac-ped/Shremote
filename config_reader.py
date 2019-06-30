import yaml
import re
import copy
import pprint
from include_loader import IncludeLoader

class CfgFormatFileException(Exception):
    pass

def wrong_type_exception(name, type, expected):
    return CfgFormatFileException(
            "Element {} is type {}. Expected: {}".format(name, type, expected)
    )

class CfgFormatException(Exception):
    pass

def verifier(fn):
    def inner(self, elem, name):
        self._names[name] = elem
        return fn(self, elem, name)
    return inner

class ConfigFormatter(object):

    TYPES = {'bool': bool,
                'int': int,
                'float': float,
                'str': str,
                None: lambda: None}

    FLAGS = ('required', 'list_ok', 'formattable')

    def __init__(self, format):
        self.format = format
        self._names = {}
        self._verify_fmt_format(format, '')
        self._check_unused_fmt_fields(format, '')

    def format_cfg(self, raw_cfg):
        cfg = ConfigEntry(raw_cfg)
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
        if (('fields' in elem) == ('format' in elem)):
            raise CfgFormatFileException("Must specify exactly one of 'fields' or 'format' in {}"
                                         .format(name))
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

class BadExecException(CfgFormatException):
    pass

class ConfigEntry(object):

    def __init__(self, raw_entry, path = [], root = None):
        if root is not None and len(path) == 0:
            raise CfgFormatException("Root is not none but path exists and is {}".format(path))
        self.__name = ".".join(str(p) for p in path)
        self.__path = path

        if isinstance(raw_entry, ConfigEntry):
            raw_entry = raw_entry.get_raw()

        self.__raw = raw_entry
        self.__types = None
        if root is None:
            self.__root = self
        else:
            self.__root = root

        self.__formattable = False
        self.__format_kwarg_obj = None

        self.__computed_subfields = {}
        self.__default_computed_subfields_enabled = False
        if isinstance(raw_entry, dict):
            self.__subfields = {}
            for k, v in raw_entry.items():
                self.__subfields[k] = ConfigEntry(v, path + [k], self.__root)
            self.__leaf = False
        elif isinstance(raw_entry, list):
            self.__subfields = []
            for i, v in enumerate(raw_entry):
                self.__subfields.append(ConfigEntry(v, path + [i], self.__root))
            self.__leaf = False
        else:
            self.__leaf = True

    def set_formattable(self):
        if not self.is_map():
            raise CfgFormatException("Only map-based containers can be set to formattable")
        self.__format_kwarg_obj = self
        self.__formattable = True
        for child in self.children():
            child._set_format_obj(self)

    def _set_format_obj(self, obj):
        self.__format_kwarg_obj = obj
        self.__formattable = True
        for child in self.children():
            child._set_format_obj(obj)

    def enable_computed_fields(self):
        self.__default_computed_subfields_enabled = True
        for child in self.children():
            child.enable_computed_fields()

    def add_computed_field(self, key, type_):
        self.__computed_subfields[key] = type_

    def get_computed_field_keys(self):
        return self.__computed_subfields.keys()

    def disable_computed_fields(self):
        self.__default_computed_subfields_enabled = False
        for child in self.children():
            child.disable_computed_fields()

    def pformat(self):
        return pprint.pformat(self.get_raw())

    def get_name(self):
        return self.__name

    def is_list(self):
        return not self.__leaf and isinstance(self.__subfields, list)

    def is_map(self):
        return not self.__leaf and isinstance(self.__subfields, dict)

    def is_leaf(self):
        return self.__leaf

    def get_raw(self):
        if self.__leaf:
            return self.__raw
        else:
            if isinstance(self.__subfields, dict):
                raw = {k: v.get_raw() for k, v in self.__subfields.items()}
            elif isinstance(self.__subfields, list):
                raw = [v.get_raw() for v in self.__subfields]
            return raw

    def setpath(self, path, value):
        if len(path) == 0:
            raise Exception("No path passsed")
        if len(path) == 1:
            self[path[0]] = ConfigEntry(value, self.__path + [path[0]], self.__root)
        else:
            if path[0] not in self:
                self[path[0]] = ConfigEntry({}, self.__path + [path[0]], self.__root)
            self[path[0]].setpath(path[1:], value)

    def getpath(self, path):
        if len(path) == 0:
            return self
        else:
            return self[path[0]].getpath(path[1:])

    def haspath(self, path):
        if len(path) == 0:
            return True
        elif self.__leaf:
            return False
        else:
            if path[0] not in self:
                return False
            return self[path[0]].haspath(path[1:])

    def allow_type(self, _type):
        if self.__types is None:
            self.__types = [_type]
        else:
            self.__types.append(_type)

    def get_types(self):
        return self.__types

    def _get_computed_field(self, key):
        if key not in self.__computed_subfields:
            raise AttributeError("Config entry '%s' does not contain key: '%s'" %
                                 (self.__name, key))
        if not self.__default_computed_subfields_enabled:
            raise AttributeError("Config entry '%s' requested computed subfield: '%s' "
                    "which was not provided to formatter" % (self.__name, key))
        return self.__computed_subfields[key]()

    def _assert_not_leaf(self, key):
        if self.__leaf:
            raise AttributeError("Config entry %s does not have %s: it is a leaf" %
                                 (self.__name, key))

    def _assert_has_attrs(self, key):
        self._assert_not_leaf(key)
        if self.is_list():
            raise AttributeError("Config entry %s does not have %s: it is a list" %
                                (self.__name, key))

    def keys(self):
        for x in self.__subfields.keys():
            yield x
        if self.__default_computed_subfields_enabled:
            for x in self.__computed_subfields.keys():
                yield x

    def items(self):
        if not self.is_map():
            raise CfgFormatException("Item {} is not a map".format(self.__name))
        for x in self.__subfields.items():
            yield x

    def children(self, recursive = False):
        if self.is_map():
            for v in self.__subfields.values():
                if recursive and not v.is_leaf():
                    for vv in v.children(recursive):
                        yield vv
                yield v
        elif self.is_list():
            for v in self.__subfields:
                if recursive and not v.is_leaf():
                    for vv in v.children(recursive):
                        yield vv
                yield v


    def __deepcopy__(self, memo):
        if self.__leaf:
            return self.__raw
        subf_copy = copy.deepcopy(self.__subfields, memo)
        cpy = ConfigEntry(subf_copy, self.__path, self.__root)
        for cfk, cfv in self.__computed_subfields.items():
            cpy.add_computed_field(cfk, cfv)
        if self.__default_computed_subfields_enabled:
            cpy.enable_computed_fields()
        return cpy

    def __getattr__(self, key):
        if key.startswith('_ConfigEntry'):
            return super(ConfigEntry, self).__getattribute__(key.replace("_ConfigEntry", ""))
        self._assert_has_attrs(key)
        if key not in self.__subfields:
            return self._get_computed_field(key)
        return self.__subfields[key]

    def __setattr__(self, key, value):
        if key.startswith('_ConfigEntry'):
            return super(ConfigEntry, self).__setattr__(key, value)
        self._assert_has_attrs(key)
        self.__subfields[key] = value

    def __setitem__(self, key, value):
        self._assert_not_leaf(key)
        self.__subfields[key] = value

    def __getitem__(self, key):
        self._assert_not_leaf(key)
        if self.is_map() and key not in self.__subfields:
            return self._get_computed_field(key)
        return self.__subfields[key]

    def __contains__(self, key):
        self._assert_not_leaf(key)
        if self.is_map():
            return key in self.__subfields
        elif isinstance(key, int):
            return key < len(self.__subfields)
        else:
            raise AttributeError("Key {} has wrong type for querying {}".format(key, self.__name))

    def __iter__(self):
        self._assert_not_leaf('__iter__')
        for x in self.__subfields:
            yield x

    def __len__(self):
        if self.__leaf:
            return len(self.__raw)
        else:
            return len(self.__subfields)

    def __str__(self):
        return str(self.format())

    @staticmethod
    def innermost_exec_str(st):
        # To start, find all $( which aren't $$(
        matches = re.finditer(r'(^|[^$])(\$\()', st)
        starts = [m.start(2) for m in matches]
        if len(starts) == 0:
            return None
        # The last match will be innermost or alone
        start_idx = starts[-1]
        end_idx = None
        stack = []
        for i in range(len(st)-1, start_idx, -1):
            if st[i] == ')':
                stack.append(i)
            if st[i] == '(' and len(stack) > 0:
                end_idx = stack.pop()
        if end_idx is None:
            raise BadExecException("Cannot find end of exec string: {}".format(st[last_match_idx:]))
        return st[start_idx:end_idx+1]

    @classmethod
    def do_eval(cls, value):
        if not isinstance(value, str):
            return value
        eval_grp = cls.innermost_exec_str(value)
        while eval_grp is not None:
            # Cut off the starting $, leaving (...)
            to_eval = eval_grp[1:]
            rep_with = str(eval(to_eval))
            value = value.replace(eval_grp, rep_with)
            eval_grp = cls.innermost_exec_str(value)
        return value

    def format(self, **kwargs):
        if not self.__formattable:
            return self.__raw
        if self.__format_kwarg_obj is not None:
            kwargobj = copy.deepcopy(self.__format_kwarg_obj)
            for k, v in kwargs.items():
                kwargobj[k] = v
        else:
            kwargobj = kwargs
        if not self.__leaf:
            return self.get_raw()
        if isinstance(self.__raw, str):
            formatted = self.__raw
            while '{' in formatted:
                try:
                    formatted = formatted.format(self.__root, **kwargobj)
                except Exception as e:
                    if self.__format_kwarg_obj is not None:
                        error_due_to_computed_fields = False
                        self.__format_kwarg_obj.enable_computed_fields()
                        try:
                            self.format(**kwargs)
                            error_due_to_computed_fields = True
                        except Exception as e:
                            pass
                        self.__format_kwarg_obj.disable_computed_fields()

                        if error_due_to_computed_fields:
                            computed_keys = self.__format_kwarg_obj.get_computed_field_keys()
                            raise CfgFormatException(
                                "Error formatting field {} '{}' due to unprovided field "
                                "(one of {})"
                                .format(self.__name, formatted, computed_keys)
                            )
                    raise
                try:
                    formatted = self.do_eval(formatted)
                except:
                    pass
            evaled = self.do_eval(formatted)
            if self.__types is not None:
                casted = False
                for __type in self.__types:
                    try:
                        evaled = __type(evaled)
                        casted = True
                        break
                    except ValueError as e:
                        raise
                        pass
                if not casted:
                    raise CfgFormatException("Could not cast {} to {} for {}"
                            .format(evaled, self.__types, self.__name))
                evaled = __type(evaled)
            return evaled
        return self.__raw

    def formatted(self, key, **kwargs):
        self._assert_has_attrs(key)
        return self.__subfields[key].format(**kwargs)

if __name__ == '__main__':
    fmtr = ConfigFormatter(yaml.load(open('cfg_format.yml', 'r'), yaml.SafeLoader))
    raw_cfg = yaml.load(open('test_valid_cfg.yml'), IncludeLoader)
    cfg = fmtr.format_cfg(raw_cfg)

    print(cfg.pformat())
    for cmd in cfg.commands:
        start = cmd.program.start.format(i=0)
        begin = cmd.begin[0].format()
        print("Comnand '{}'\n\tstarts at time {}".format(start, begin))