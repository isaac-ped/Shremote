import copy
import re
import pprint
from collections import defaultdict

class CfgFormatException(Exception):
    pass

class BadExecException(CfgFormatException):
    pass

class FmtConfig(object):
    """ Formattable config """

    def __init__(self, raw_entry, path = [], root = None, formattable=False):
        if root is not None and len(path) == 0:
            raise CfgFormatException("Root is not none but path exists and is {}".format(path))
        self.__name = ".".join(str(p) for p in path)
        self.__path = path

        if isinstance(raw_entry, FmtConfig):
            raw_entry = raw_entry.get_raw()

        self.__raw = raw_entry
        self.__types = None
        if root is None:
            self.__root = self
        else:
            self.__root = root

        self.__formattable = formattable
        self.__format_kwarg_obj = None

        self.__computed_subfields = {}
        self.__default_computed_subfields_enabled = False
        if isinstance(raw_entry, dict):
            if isinstance(raw_entry, defaultdict):
                self.__subfields = raw_entry
            else:
                self.__subfields = {}
                for k, v in raw_entry.items():
                    self.__subfields[k] = FmtConfig(v, path + [k], self.__root, self.__formattable)
            self.__leaf = False
        elif isinstance(raw_entry, list):
            self.__subfields = []
            for i, v in enumerate(raw_entry):
                self.__subfields.append(FmtConfig(v, path + [i], self.__root, self.__formattable))
            self.__leaf = False
        else:
            self.__leaf = True

    def get_root(self):
        return self.__root

    def set_formattable(self):
        if not self.is_map():
            raise CfgFormatException("Only map-based containers can be set to formattable")
        self.__format_kwarg_obj = self
        self.__formattable = True
        for child in self.children():
            child._set_format_root(self)

    def _set_format_root(self, obj):
        self.__format_kwarg_obj = obj
        self.__formattable = True
        for child in self.children():
            child._set_format_root(obj)

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
            self[path[0]] = FmtConfig(value, self.__path + [path[0]], self.__root)
        else:
            if path[0] not in self:
                self[path[0]] = FmtConfig({}, self.__path + [path[0]], self.__root)
            self[path[0]].setpath(path[1:], value)

    def mergepath(self, path, value):
        if len(path) == 0:
            raise Exception("No path passsed")
        if len(path) == 1:
            value = FmtConfig(value, self.__path + [path[0]], self.__root)
            if path[0] in self and self[path[0]].is_map():
                for k, v in value.items():
                    if k not in self[path[0]]:
                        self[path[0]][k] = v
            else:
                self[path[0]] = value
        else:
            if path[0] not in self:
                self[path[0]] = FmtConfig({}, self.__path + [path[0]], self.__root)
            self[path[0]].mergepath(path[1:], value)


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
        try:
            field = FmtConfig(self.__computed_subfields[key](), self.__path + [key])
            field.enable_computed_fields()
            return field
        except KeyError:
            raise KeyError("Config entry '%s' does not contain key: '%s'" %
                                 (self.__name, key))

    def _assert_not_leaf(self, key):
        if self.__leaf:
            raise AttributeError("Config entry '%s' does not have '%s': it is a leaf" %
                                 (self.__name, key))

    def _assert_has_attrs(self, key):
        self._assert_not_leaf(key)
        if self.is_list():
            raise AttributeError("Config entry '%s' does not have '%s': it is a list" %
                                (self.__name, key))

    def keys(self):
        for x in self.__subfields.keys():
            yield x
        if self.__default_computed_subfields_enabled:
            for x in self.__computed_subfields.keys():
                yield x

    def values(self):
        if not self.is_map():
            raise CfgFormatException("Item {} is not a map".format(self.__name))
        for x in self.__subfields.values():
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
        cpy = FmtConfig(subf_copy, self.__path, self.__root)
        for cfk, cfv in self.__computed_subfields.items():
            cpy.add_computed_field(cfk, cfv)
        if self.__default_computed_subfields_enabled:
            cpy.enable_computed_fields()
        return cpy

    def _get_key(self, key):
        try:
            return self.__subfields[key]
        except KeyError:
            if self.__default_computed_subfields_enabled:
                try:
                    return self._get_computed_field(key)
                except KeyError:
                    pass
            else:
                try:
                    self._get_computed_field(key)
                    raise CfgFormatException(
                            "Config entry '{}' requested unprovided computed subfield: '{}'"
                            .format(self.__name, key))
                except KeyError:
                    pass
            raise KeyError("Config entry '{}' does not contain key '{}'".format(
                            self.__name, key))

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return FmtConfig(default)

    def __getattr__(self, key):
        if key.startswith('_FmtConfig'):
            return super(FmtConfig, self).__getattribute__(key.replace("_FmtConfig", ""))
        self._assert_has_attrs(key)
        return self._get_key(key)

    def __setattr__(self, key, value):
        if key.startswith('_FmtConfig'):
            return super(FmtConfig, self).__setattr__(key, value)
        self._assert_has_attrs(key)
        self.__subfields[key] = FmtConfig(value, self.__path + [key], self.__root)

    def __setitem__(self, key, value):
        self._assert_not_leaf(key)
        try:
            self.__subfields[key] = FmtConfig(value, self.__path + [key], self.__root)
        except (TypeError, KeyError) as e:
            raise CfgFormatException("Error setting {} in {}: {}".format(key, self.__path, e))

    def __getitem__(self, key):
        self._assert_not_leaf(key)
        return self._get_key(key)

    def __contains__(self, key):
        self._assert_not_leaf(key)
        if self.is_map():
            return key in self.__subfields
        elif isinstance(key, int):
            return key < len(self.__subfields)
        else:
            raise AttributeError("Key '{}' has wrong type ({}) for querying '{}' ({})"
                                 .format(key, type(key), self.__path, type(self.__raw)))

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
        return str(self.format(_strip_escaped_eval=False))


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

    def format(self, _strip_escaped_eval = True, _check_computed = True, **kwargs):
        if not self.__formattable:
            return self.get_raw()
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
            # Search for { which is not followed or preceeded by {
            while re.search('(?<!{){[^{]', formatted) is not None:
                try:
                    if isinstance(formatted, str):
                        formatted = formatted.format(self.__root, **kwargobj)
                    else:
                        formatted = formatted.format(_strip_escaped_eval = False, **kwargobj)
                except KeyError as e:
                    # Check if error would have arisen if computed fields presentt
                    if self.__format_kwarg_obj is not None and _check_computed:
                        error_due_to_computed_fields = False
                        self.__format_kwarg_obj.enable_computed_fields()
                        try:
                            self.format(_strip_escaped_eval = False, _check_computed = False,
                                        **kwargs)

                            computed_keys = self.__format_kwarg_obj.get_computed_field_keys()
                            raise CfgFormatException(
                                "Error formatting field {} '{}' due to unprovided field "
                                "(likely one of {})"
                                .format(self.__name, formatted, computed_keys)
                            )

                        except Exception as e:
                            self.__format_kwarg_obj.disable_computed_fields()

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
            if isinstance(evaled, str) and _strip_escaped_eval:
                evaled = evaled.replace('$$(', '$(')
                evaled = evaled.format()
            return evaled
        return self.__raw

    def formatted(self, key, *args, **kwargs):
        self._assert_has_attrs(key)
        return self.__subfields[key].format(**kwargs)


