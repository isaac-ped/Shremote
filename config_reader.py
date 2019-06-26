import yaml
import re
import copy
import pprint
from include_loader import IncludeLoader

class CfgFormatFileException(Exception):
    pass

def missing_field_exception(name, key):
    return CfgFormatFileException("Element {} lacks '{}'".format(name, key))

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

    def __init__(self, format):
        self.format = format
        self._names = {}
        self._verify_format(format, '')
        self._check_verification(format, '')

    def format_cfg(self, raw_cfg):
        cfg = ConfigEntry(raw_cfg)
        self._fix_cfg_format(cfg, [], self.format, None, True)
        return cfg

    def _get_reference_fmt(self, referent_path):
        reference_fmt = self.format
        for keyname in referent_path:
            for field in reference_fmt['fields']:
                if field['key'] == keyname:
                    reference_fmt = field['format']
                    break
            else:
                raise CfgFormatFileException("Reference format {} does not exist in cfg format file".format(fmt_referent_name))
        return reference_fmt


    def _fix_cfg_format(self, cfg, field_path, fmt, parent_fmt, exists):
        if isinstance(fmt['type'], list) or fmt['type'] in self.TYPES:
            if cfg.haspath(field_path):
                types = fmt['type'] if isinstance(fmt['type'], list) else [fmt['type']]
                for type_ in types:
                    cfg.getpath(field_path).allow_type(self.TYPES[type_])
        elif fmt['type'] == 'map':
            if 'fields' in fmt:
                for field in fmt['fields']:
                    self._fix_cfg_field(cfg, field_path, field, fmt, exists)
            if 'format' in fmt:
                if cfg.haspath(field_path):
                    sub_fmt = fmt['format']
                    for cfg_field in cfg.getpath(field_path):
                        self._fix_cfg_format(cfg, field_path + [cfg_field], sub_fmt, fmt, exists)
        elif fmt['type'] == 'list':
            if cfg.haspath(field_path):
                sub_fmt = fmt['format']
                for i in range(len(cfg.getpath(field_path))):
                    self._fix_cfg_format(cfg, field_path + [i], sub_fmt, fmt, exists)
        elif fmt['type'] == 'reference':
            print(field_path, "reference")
            referent_path = fmt['referent']
            if cfg.haspath(field_path) and cfg.getpath(field_path).is_leaf():
                cfg_entry = cfg.getpath(field_path)
                referent = cfg.getpath(referent_path + [cfg_entry.format()])
                cfg.setpath(field_path, referent)
            else:
                reference_fmt = self._get_reference_fmt(referent_path)
                if reference_fmt['type'] != 'map' or 'format' not in reference_fmt:
                    raise CfgFormatFileException("Reference format {} is not an unspecified map type".format(referent_path))
                reference_fmt = reference_fmt['format']

                self._fix_cfg_format(cfg, field_path, reference_fmt, cfg.haspath(field_path), cfg.haspath(field_path))
        elif fmt['type'] == 'inherit':
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
                        raise CfgFormatFileException("Parent format {} does not exist in {}".format(inherited_field_name, inherited_field))
                print("Fixing" + str(field_path) + str(inherited_field))
                self._fix_cfg_field(cfg, field_path[:-1], inherited_field, None, True)
            else:
                parent_path = field_path[:-1] + fmt['parent']
                if not cfg.haspath(parent_path):
                    raise CfgFormatException("Config lacks paths {} and {}".format(field_path, parent_path))
                cfg.setpath(field_path, cfg.getpath(parent_path))
        elif fmt['type'] == 'override':
            override = fmt['overrides']
            if not cfg.haspath(field_path):
                if not cfg.haspath(override):
                    raise CfgFormatException("Config lacks paths {} and {}".format(field_path, override))
                cfg.setpath(field_path, cfg.getpath(override))
            else:
                reference_fmt = self._get_reference_fmt(override)
                if reference_fmt['type'] != 'map' or 'fields' not in reference_fmt:
                    raise CfgFormatFileException("Reference format {} is not specified map type"
                                                 .format(override))
                self._fix_cfg_format(cfg, field_path, reference_fmt, parent_fmt, True)
        else:
            raise Exception("HOW DID YOU DO THIS")

    def _fix_cfg_field(self, cfg, field_path, field, parent_fmt, exists=True):
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
                print("Set" + str(keypath) +"to list")
            else:
                print(str(keypath)+  "already")

            if not field['format']['type'] == 'list':
                list_fmt = {'type': 'list', 'format': field['format']}
                field['format'] = list_fmt

        self._fix_cfg_format(cfg, keypath, field['format'], parent_fmt, exists)

        if exists and field_required and not cfg.haspath(keypath):
            raise CfgFormatException("Entry {} DNE in config".format(keypath))


    def _check_verification(self, format, name):
        if name not in self._names:
            raise CfgFormatFileException("Unused field: %s" % name)
        if isinstance(format, list):
            for i, elem in enumerate(format):
                ename = name + '[%d]' % i
                self._check_verification(elem, ename)
        elif isinstance(format, dict):
            for k, elem in format.items():
                vname = name + '.' + k
                self._check_verification(elem, vname)

    def _verify(self, elem, name, key, type_=None, optional=False):
        if optional and key not in elem:
            if type_ is not None:
                elem[key] = type_()
            else:
                elem[key] = None
        sub, sname = self._get(elem, name, key)
        if type_ is not None and not isinstance(elem[key], type_):
            raise wrong_type_exception(sname, type(elem[key]), type_)
        if isinstance(sub, list):
            for i, _ in enumerate(sub):
                self._names[sname + '[%d]' % i] = sub

    def _get(self, elem, name, key):
        subname = name + '.' + key
        if key not in elem:
            raise missing_field_exception(name, key)
        self._names[subname] = elem[key]
        return elem[key], subname

    def _verify_list(self, elem, name, verifier):
        if not isinstance(elem, list):
            raise wrong_type_exception(name, type(elem), list)
        for i, lelem in enumerate(elem):
            verifier(lelem, name + '[%d]' % i)

    @verifier
    def _verify_map_type(self, elem, name):
        if (('fields' in elem) == ('format' in elem)):
            raise CfgFormatFileException("Must specify exactly one of 'fields' or 'format' in {}"
                                         .format(name))
        if 'fields' in elem:
            fields, fname = self._get(elem, name, 'fields')
            self._verify_fields(fields, fname)
        if 'format' in elem:
            fmt, fname = self._get(elem, name,  'format')
            self._verify_format(fmt, fname)

    @verifier
    def _verify_list_type(self, elem, name):
        fmts, fname = self._get(elem, name, 'format')
        self._verify_format(fmts, fname)

    @verifier
    def _verify_reference_type(self, elem, name):
        self._verify(elem, name, 'referent', list)

    @verifier
    def _verify_inherit_type(self, elem, name):
        self._verify(elem, name, 'parent', list)

    @verifier
    def _verify_override_type(self, elem, name):
        self._verify(elem, name, 'overrides', list)

    @verifier
    def _verify_format(self, elem, name):
        etype, tname = self._get(elem, name, 'type')
        if isinstance(etype, list):
            self._verify(elem, name, 'type', list)
            if not all([et in self.TYPES for et in etype]):
                raise CfgFormatFileException("For reference element {}: not all types are basic".format(name))
            return

        if etype == 'map':
            self._verify_map_type(elem, name)
        elif etype == 'list':
            self._verify_list_type(elem, name)
        elif etype == 'reference':
            self._verify_reference_type(elem, name)
        elif etype == 'inherit':
            self._verify_inherit_type(elem, name)
        elif etype == 'override':
            self._verify_override_type(elem, name)
        elif etype not in self.TYPES:
            raise CfgFormatFileException("Unknown type {} for {}".format(etype, tname))

    @verifier
    def _verify_field_elem(self, elem, name):
        self._verify(elem, name, 'key', str)
        fmts, fname = self._get(elem, name, 'format')
        self._verify_format(fmts, fname)
        self._verify(elem, name, 'aliases', list, optional=True)
        self._verify(elem, name, 'default', optional=True)
        self._verify(elem, name, 'flags', list, optional=True)

    @verifier
    def _verify_fields(self, elem, name):
        self._verify_list(elem, name, self._verify_field_elem)

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

        if isinstance(raw_entry, dict):
            self.__subfields = {}
            for k, v in raw_entry.items():
                self.__subfields[k] = ConfigEntry(v, path + [k], root)
            self.__leaf = False
        elif isinstance(raw_entry, list):
            self.__subfields = []
            for i, v in enumerate(raw_entry):
                self.__subfields.append(ConfigEntry(v, path + [i], root))
            self.__leaf = False
        else:
            self.__leaf = True

    def pformat(self):
        return pprint.pformat(self.get_raw())

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

    def _assert_not_leaf(self, key):
        if self.__leaf:
            raise AttributeError("Config entry %s does not have %s: it is a leaf" %
                                 (self.__name, key))

    def _assert_has_attrs(self, key):
        self._assert_not_leaf(key)
        if isinstance(self.__subfields, list):
            raise AttributeError("Config entry %s does not have %s: it is a list" %
                                (self.__name, key))
    def __getattr__(self, key):
        if key.startswith('_ConfigEntry'):
            return super(ConfigEntry, self).__getattribute__(key.replace("_ConfigEntry", ""))
        self._assert_has_attrs(key)
        if key not in self.__subfields:
            raise AttributeError("Config entry '%s' does not contain key: '%s'" %
                                 (self.__name, key))
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
        return self.__subfields[key]

    def __contains__(self, key):
        self._assert_not_leaf(key)
        if isinstance(self.__subfields, dict):
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
        return len(self.__raw)

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

    @staticmethod
    def generous_cast(value):
        try:
            return int(value)
        except:
            try:
                return float(value)
            except:
                return value

    @classmethod
    def do_eval(cls, value):
        if not isinstance(value, str):
            return value
        eval_grp = cls.innermost_exec_str(value)
        while eval_grp is not None:
            # Cut off the starting $, leaving (...)
            to_eval = eval_grp[1:]
            rep_with = str(eval(value))
            value = value.replace(eval_grp, rep_with)
            eval_grp = cls.innermost_exec_str(value)
        else:
            return cls.generous_cast(value)

    def format(self, **kwargs):
        if not self.__leaf:
            raise AttributeError("Attempted to format non-leaf attribute %s" % self.__name)
        if isinstance(self.__raw, str):
            formatted = self.__raw
            while '{' in formatted:
                formatted = formatted.format(self.__root, **kwargs)
                try:
                    formatted = str(self.do_eval(formatted))
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
                    except:
                        pass
                if not casted:
                    raise CfgFormatException("Could not cast {} to {} for {}"
                            .format(evaled, self.__types, self.__name))
                evaled = __type(evaled)
            return evaled

    def formatted(self, key, **kwargs):
        self._assert_has_attrs(key)
        return self.__subfields[key].format(**kwargs)

if __name__ == '__main__':
    fmtr = ConfigFormatter(yaml.load(open('cfg_format.yml', 'r'), yaml.SafeLoader))
    raw_cfg = yaml.load(open('test_valid_cfg.yml'), IncludeLoader)
    print(fmtr.format_cfg(raw_cfg).pformat())
