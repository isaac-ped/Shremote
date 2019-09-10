import copy
import re
import pprint
from collections import defaultdict

class CfgKeyError(KeyError):
    pass

class CfgFormatException(Exception):
    pass

class BadExecException(CfgFormatException):
    pass

class FmtConfig(object):
    """ Formattable config """

    __format_kwargs = None

    def __init__(self, raw_entry, path = [], root = None, formattable=False, computed=False):
        if root is None and len(path) > 0:
            raise CfgFormatException("Root is not none and path DNE".format(path))
        self.__name = ".".join(str(p) for p in path)
        self.__path = path
        self.__is_computed = computed
        self.__formattable = formattable
        self.__formattable_root = None
        self.__default_computed_subfields_enabled = False
        self.__types = None
        if root is None:
            self.__root = self
        else:
            self.__root = root

        self.set_value(raw_entry)

    def set_value(self, raw_entry):
        if isinstance(raw_entry, FmtConfig):
            if raw_entry.is_map():
                computed_mask = {k: v.is_computed() for k, v in raw_entry.items()}
            elif raw_entry.is_list():
                computed_mask = {i: v.is_computed() for i, v in enumerate(raw_entry)}
            else:
                computed_mask = defaultdict(lambda : raw_entry.is_computed())
                computed = raw_entry.is_computed()
            raw_entry = raw_entry.get_raw()
        else:
            computed_mask = defaultdict(lambda: False)

        self.__raw = raw_entry

        if isinstance(raw_entry, dict):
            if isinstance(raw_entry, defaultdict):
                self.__subfields = defaultdict(lambda : FmtConfig( raw_entry.default_factory(), self.__path + ['?'], self.__root, self.__formattable, True))
            else:
                self.__subfields = {}
                for k, v in raw_entry.items():
                    self.__subfields[k] = FmtConfig(v, self.__path + [k], self.__root, self.__formattable, computed_mask[k])
            self.__leaf = False
        elif isinstance(raw_entry, list):
            self.__subfields = []
            for i, v in enumerate(raw_entry):
                self.__subfields.append(FmtConfig(v, self.__path + [i], self.__root, self.__formattable, computed_mask[i]))
            self.__leaf = False
        else:
            self.__leaf = True

    def get_root(self):
        return self.__root

    def set_list_ok(self):
        self.__list_ok = True

    def set_formattable(self):
        if not self.is_map():
            raise CfgFormatException("Only map-based containers can be set to formattable")
        self.__formattable_root = self
        self.__formattable = True
        for child in self.children(True):
            child._set_format_root(self)

    def _set_format_root(self, obj):
        self.__formattable_root = obj
        self.__formattable = True

    def set_format_kwargs(self, kwargs):
        if self.__formattable_root is not None:
            FmtConfig.__format_kwargs = copy.deepcopy(self.__formattable_root)
        else:
            FmtConfig.__format_kwargs = FmtConfig({}, self.__path, self.__root, self.__formattable, True)
        for k, v in kwargs.items():
            FmtConfig.__format_kwargs[k] = v

    def set_computed(self):
        self.__is_computed = True
        for child in self.children():
            child.set_computed()

    def is_computed(self):
        return self.__is_computed

    def enable_computed_fields(self):
        self.__default_computed_subfields_enabled = True
        for child in self.children():
            child.enable_computed_fields()

    def add_computed_field(self, key, val):
        self.__subfields[key] = FmtConfig(val, self.__path + [key], self.__root, self.__formattable, True)

    def get_computed_field_keys(self):
        if not self.is_map():
            return set()
        keys = set()
        for key, val in self.items():
            if val.is_computed():
                keys.add(key)
        for child in self.children():
            if child.is_map():
                keys |= child.get_computed_field_keys()
        return keys

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

    def get_subfields(self):
        return self.__subfields

    def get_raw(self):
        if self.__leaf:
            return self.__raw
        else:
            if isinstance(self.__subfields, defaultdict):
                raw = defaultdict(self.__subfields.default_factory)
                for k, v in self.__subfields.items():
                    raw[k] = v
            elif isinstance(self.__subfields, dict):
                raw = {k: v.get_raw() for k, v in self.__subfields.items() \
                        if self.__default_computed_subfields_enabled or not v.is_computed()}
            elif isinstance(self.__subfields, list):
                raw = [v.get_raw() for v in self.__subfields]
            return raw

    def setpath(self, path, value, is_computed=False):
        if len(path) == 0:
            raise Exception("No path passsed")
        if len(path) == 1:
            self[path[0]] = FmtConfig(value, self.__path + [path[0]], self.__root, self.__formattable, is_computed or self.__is_computed)
        else:
            if path[0] not in self:
                self[path[0]] = FmtConfig({}, self.__path + [path[0]], self.__root, self.__formattable, is_computed or self.__is_computed)
            self[path[0]].setpath(path[1:], value, is_computed or self.__is_computed)

    def merge(self, value):
        value = FmtConfig(value, self.__path, self.__root)
        for k, v in value.items():
            if k not in self:
                self[k] = v

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


    def getpath(self, path, computed_ok=False):
        if len(path) == 0:
            if self.__is_computed and not computed_ok and not self.__default_computed_subfields_enabled:
                raise CfgFormatException("Returning computed field")
            return self
        else:
            return self[path[0]].getpath(path[1:])

    def haspath(self, path, computed_ok=True):
        if len(path) == 0:
            if (not self.__is_computed) or computed_ok or self.__default_computed_subfields_enabled:
                return True
            return False
        elif self.__leaf:
            return False
        else:
            if not isinstance(path[0], int) and self.is_list():
                return False
            if path[0] not in self:
                return False
            return self[path[0]].haspath(path[1:], computed_ok)

    def allow_type(self, _type):
        if self.__types is None:
            self.__types = [_type]
        else:
            self.__types.append(_type)

    def get_types(self):
        return self.__types

    def _assert_not_leaf(self, key):
        if self.__leaf:
            raise AttributeError("Config entry '%s' does not have '%s': it is a leaf (%s)" %
                                 (self.__name, key, self.__raw))

    def _assert_has_attrs(self, key):
        self._assert_not_leaf(key)
        if self.is_list() and not self.__list_ok:
            raise AttributeError("Config entry '%s' does not have '%s': it is a list" %
                                (self.__name, key))

    def keys(self):
        for x in self.__subfields.keys():
            if self.__default_computed_subfields_enabled or not self.__subfields[x].is_computed():
                yield x

    def values(self):
        if not self.is_map():
            raise CfgFormatException("Item {} is not a map ".format(self.__name))
        for x in self.__subfields.values():
            if self.__default_computed_subfields_enabled or not x.is_computed():
                yield x

    def items(self):
        if not self.is_map():
            raise CfgFormatException("Item {} is not a map ".format(self.__name))
        for x in self.__subfields.items():
            if self.__default_computed_subfields_enabled or not x[1].is_computed():
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
            return FmtConfig(self.__raw, self.__path, self.__root, self.__formattable, self.__is_computed)

        subf_copy = copy.deepcopy(self.__subfields, memo)

        cpy = FmtConfig(subf_copy, self.__path, self.__root, self.__formattable, self.__is_computed)

        if self.__default_computed_subfields_enabled:
            cpy.enable_computed_fields()
        return cpy

    def _get_key(self, key, computed_ok = False):
        try:
            rtn = self.__subfields[key]
            if rtn.is_computed() and (not computed_ok) and (not self.__default_computed_subfields_enabled):
                raise CfgFormatException(
                        "Config entry '{}' requested unprovided computed subfield: '{}'"
                        .format(self.__name, key))
            return rtn
        except TypeError:
            if self.__list_ok:
                try:
                    return self.__subfields[0][key]
                except:
                    pass
            raise
        except KeyError:
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
        self.__subfields[key] = FmtConfig(value, self.__path + [key], self.__root, self.__is_computed)

    def __setitem__(self, key, value):
        self._assert_not_leaf(key)
        try:
            self.__subfields[key] = FmtConfig(value, self.__path + [key], self.__root, self.__is_computed)
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

        if not self.__leaf and self.__types is not None:
            raise Exception("Could not cast {} ({}) to appropriate type! It is not a leaf node"
                            .format(self.__name, self.__raw))

        if not self.__leaf:
            return self.get_raw()

        if isinstance(self.__raw, str):
            if _strip_escaped_eval:
                self.set_format_kwargs(kwargs)
            formatted = self.__raw
            # Search for { which is not followed or preceeded by {
            while re.search('(?<!{){[^{]', formatted) is not None:
                try:
                    if isinstance(formatted, str):
                        formatted = formatted.format(self.__root, **self.__format_kwargs)
                    else:
                        formatted = formatted.format(_strip_escaped_eval = False, **self.__format_kwargs)
                except CfgKeyError as e:
                    raise
                except KeyError as e1:
                    # If default subfields are already enabled, there's an issue
                    if self.__default_computed_subfields_enabled:
                        raise
                    # Check if error would have arisen if computed fields presentt
                    if self.__format_kwargs is not None and _check_computed:
                        error_due_to_computed_fields = False
                        self.__format_kwargs.enable_computed_fields()
                        try:
                            self.format(_strip_escaped_eval = False, _check_computed = False,
                                        **self.__format_kwargs)

                            computed_keys = self.__format_kwargs.get_computed_field_keys()
                            raise CfgFormatException(
                                "Error formatting field {} '{}' due to unprovided field "
                                "(likely one of {})"
                                .format(self.__name, formatted, computed_keys)
                            )

                        except Exception as e2:
                            self.__format_kwargs.disable_computed_fields()
                    raise CfgKeyError("Error formatting {} ({}): {}".format(self.__name, formatted, e1.args[0]))
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
                        continue
                if not casted:
                    raise CfgFormatException("Could not cast {} to {} for {}"
                            .format(evaled, self.__types, self.__name))
                evaled = __type(evaled)
            if isinstance(evaled, str) and _strip_escaped_eval:
                evaled = evaled.replace('$$(', '$(')
                evaled = evaled.format()
            if _strip_escaped_eval:
                self.set_format_kwargs({})
            return evaled
        return self.__raw

    def formatted(self, key, *args, **kwargs):
        self._assert_has_attrs(key)
        return self.__subfields[key].format(**kwargs)


