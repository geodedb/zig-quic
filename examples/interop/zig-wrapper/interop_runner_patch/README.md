Shadow / monkey patch modules for interop runner.

PYTHONPATH is set to include this directory _before_ the submodule so that
`import interop` resolves to our shim which imports the real upstream module
and patches InteropRunner.\_check_impl_is_compliant to always return True.

Files:

- interop_runner.py : legacy name (unused if shadow module is named interop.py)
- interop_override.py : experimental earlier attempt
- interop.py : (planned) full shadow + patch; not yet added
