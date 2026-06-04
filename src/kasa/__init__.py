"""
kasa — a personal, portable, single-file encrypted vault.

Public engine API (stable):
    write_vault, read_vault, rewrap_password, read_header,
    make_workdir, secure_wipe, pick_runtime_base,
    KDF_TIERS, DEFAULT_TIER, MAGIC, FORMAT_VERSION
"""
from ._version import __version__
from .core import (
    DEFAULT_TIER,
    FORMAT_VERSION,
    KDF_TIERS,
    MAGIC,
    make_workdir,
    pick_runtime_base,
    read_header,
    read_vault,
    rewrap_password,
    secure_wipe,
    write_vault,
)

__all__ = [
    "__version__",
    "write_vault",
    "read_vault",
    "rewrap_password",
    "read_header",
    "make_workdir",
    "secure_wipe",
    "pick_runtime_base",
    "KDF_TIERS",
    "DEFAULT_TIER",
    "MAGIC",
    "FORMAT_VERSION",
]
