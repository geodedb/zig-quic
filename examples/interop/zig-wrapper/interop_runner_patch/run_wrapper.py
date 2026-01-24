"""Wrapper entrypoint guaranteeing our shadow interop patch loads before upstream run.py.

Executed instead of the upstream run.py. Ensures sys.path[0] is this patch
directory so that `import interop` resolves to the shadow module here, which
monkey patches InteropRunner._check_impl_is_compliant. Then delegates to
upstream run.main().
"""

from __future__ import annotations

import os, sys

PATCH_DIR = os.path.abspath(os.path.dirname(__file__))
# quic-interop-runner is a sibling of zig-wrapper under examples/interop
RUNNER_DIR = os.path.abspath(os.path.join(PATCH_DIR, '..', '..', 'quic-interop-runner'))

if RUNNER_DIR not in sys.path:
    sys.path.append(RUNNER_DIR)

# Import shadow first (located in PATCH_DIR which is sys.path[0])
import interop  # noqa: F401

from run import main  # type: ignore

if __name__ == '__main__':  # pragma: no cover
    sys.exit(main())
