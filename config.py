# -*- coding: utf-8 -*-

"""
Created on Thu Aug 15 22:31:34 2024
@author: Ian Malloy
"""
import copy
import re
import yaml
from typing import Any, Dict, List, Optional

class tf:
    # Regular expressions for parsing
    _PARAM_RE = re.compile(
        r"""
        (?P<name>[a-zA-Z][\w\.]*)(?P<bracketed_index>\[?[0-9]*\]?)  
        \s*=\s*
        ((?P<val>'(.*?)' | "(.*?)" | [^,\[]* | \[[^\]]*\])) 
        ($|,\s*)""", re.VERBOSE)

    # YAML loader configuration for float numbers
    _LOADER = yaml.FullLoader
    _LOADER.add_implicit_resolver(
        'tag:yaml.org,2002:float',
        re.compile(r'''
            ^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+]?[0-9]+)?
            | [-+]?(?:[0-9][0-9_]*)(?:[eE][-+]?[0-9]+)
            | \.[0-9_]+(?:[eE][-+][0-9]+)?
            | [-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\\.[0-9_]*)$''', re.X),
        list('-+0123456789.'))

    class ParamsDict:
        """A container class for hyperparameters with validation."""
        RESERVED_ATTR = ['_locked', '_restrictions']

        def __init__(self, default_params: Optional[Dict[str, Any]] = None, restrictions: Optional[List[str]] = None):
            self._locked = False
            self._restrictions = restrictions if restrictions else []
            self.override(default_params or {}, is_strict=False)

        def _set(self, key: str, value: Any):
            self.__dict__[key] = tf.ParamsDict(value) if isinstance(value, dict) else copy.deepcopy(value)

        def __setattr__(self, key: str, value: Any):
            if key in tf.ParamsDict.RESERVED_ATTR:
                super().__setattr__(key, value)
            elif key not in self.__dict__:
                raise KeyError(f'The key `{key}` does not exist. Use `override` to add new keys.')
            elif self._locked:
                raise ValueError('ParamsDict is locked. No changes allowed.')
            else:
                self._set(key, value)

        def __getattr__(self, key: str) -> Any:
            if key not in self.__dict__:
                raise AttributeError(f'The key `{key}` does not exist.')
            return self.__dict__[key]

        def override(self, override_params: Dict[str, Any], is_strict: bool = True):
            if self._locked:
                raise ValueError('ParamsDict is locked. No changes allowed.')
            self._override(override_params, is_strict)

        def _override(self, override_dict: Dict[str, Any], is_strict: bool):
            for key, value in override_dict.items():
                if key in tf.ParamsDict.RESERVED_ATTR:
                    raise KeyError(f'The key `{key}` is reserved.')
                if key not in self.__dict__:
                    if is_strict:
                        raise KeyError(f'The key `{key}` does not exist. Use `override` with `is_strict=False` to add new keys.')
                    else:
                        self._set(key, value)
                else:
                    current_value = self.__dict__[key]
                    if isinstance(value, dict):
                        current_value._override(value, is_strict)
                    elif isinstance(value, tf.ParamsDict):
                        current_value._override(value.as_dict(), is_strict)
                    else:
                        self.__dict__[key] = copy.deepcopy(value)

        def lock(self):
            self._locked = True

        def as_dict(self) -> Dict[str, Any]:
            return {k: (v.as_dict() if isinstance(v, tf.ParamsDict) else copy.deepcopy(v)) for k, v in self.__dict__.items() if k not in tf.ParamsDict.RESERVED_ATTR}

        def validate(self):
            """Validate parameter consistency based on restrictions."""
            def _get_kv(dotted_string: str, params_dict: Dict[str, Any]) -> (Optional[str], Any):
                if re.match(r'^[-+]?\d+(\.\d+)?$', dotted_string):
                    return None, float(dotted_string) if dotted_string != 'None' else None
                tokens = dotted_string.split('.')
                value = params_dict
                for token in tokens:
                    value = value[token]
                return tokens[-1], value

            def _check_relation(left_v: Any, right_v: Any, operator: str):
                return eval(f'left_v {operator} right_v')

            params_dict = self.as_dict()
            for restriction in self._restrictions:
                for operator in ['==', '!=', '<=', '<', '>=', '>']:
                    if operator in restriction:
                        tokens = restriction.split(operator)
                        left_k, left_v = _get_kv(tokens[0].strip(), params_dict)
                        right_k, right_v = _get_kv(tokens[1].strip(), params_dict)
                        if _check_relation(left_v, right_v, operator):
                            raise KeyError(f'Found inconsistency between `{tokens[0]}` and `{tokens[1]}`.')
                        break
                else:
                    raise ValueError(f'Unsupported relation in restriction: `{restriction}`.')

        def read_yaml_to_params_dict(self, file_path: str) -> 'tf.ParamsDict':
            """Reads a YAML file and returns a ParamsDict."""
            with tf.io.gfile.GFile(file_path, 'r') as f:
                return self.ParamsDict(yaml.load(f, Loader=self._LOADER))
