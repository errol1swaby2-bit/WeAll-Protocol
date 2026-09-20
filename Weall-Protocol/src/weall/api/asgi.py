from __future__ import annotations

"""Production ASGI entrypoint with explicit runtime boot semantics."""

from weall.api.app import _module_app_boot_runtime_default, create_app

app = create_app(boot_runtime=_module_app_boot_runtime_default())
