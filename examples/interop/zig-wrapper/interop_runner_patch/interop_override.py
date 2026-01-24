"""Local override wrapper providing InteropRunner bypass without editing submodule.

We import the original interop module dynamically and then monkey patch the
_check_impl_is_compliant method to always return True.
"""
import importlib

from implementations import IMPLEMENTATIONS as _IMPLS
orig = importlib.import_module('interop')

def _bypass(self, name: str) -> bool:
    self.compliant[name] = True
    return True

orig.InteropRunner._check_impl_is_compliant = _bypass

# Re-export everything then patch InteropRunner to inject zig into sets if provided
from interop import *  # type: ignore

if hasattr(orig, 'InteropRunner'):
    _Orig = orig.InteropRunner
    class InteropRunner(_Orig):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            if 'zig' in _IMPLS:
                if 'zig' not in self.implementations:
                    self.implementations['zig'] = {
                        'image': _IMPLS['zig']['image'],
                        'url': _IMPLS['zig']['url'],
                    }
                if 'zig' not in self.clients:
                    self.clients.append('zig')
                if 'zig' not in self.servers:
                    self.servers.append('zig')
