import json
import os
from enum import Enum

class Role(Enum):
    BOTH = "both"
    SERVER = "server"
    CLIENT = "client"

# Load upstream implementations.json without modifying it
with open("implementations.json", "r") as f:
    data = json.load(f)

# Build IMPLEMENTATIONS mapping and inject a local 'zig' entry dynamically
IMPLEMENTATIONS = {}
for name, val in data.items():
    role = val.get("role", "both")
    IMPLEMENTATIONS[name] = {
        "image": val["image"],
        "url": val.get("url", ""),
        "role": Role.SERVER if role == "server" else Role.CLIENT if role == "client" else Role.BOTH,
    }

# Inject/override zig entry if requested via environment (no file modification)
zig_image = os.environ.get("ZIG_IMAGE_TAG")
zig_url = os.environ.get("ZIG_IMPL_URL", "https://github.com/spyder/zig-quic")
if zig_image:
    IMPLEMENTATIONS["zig"] = {"image": zig_image, "url": zig_url, "role": Role.BOTH}
