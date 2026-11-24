"""Compatibility entry point; implementation lives in reconforge.asset_context."""
import importlib
import sys

_implementation = importlib.import_module("reconforge.asset_context")

if __name__ == "__main__":
    if hasattr(_implementation, "main"):
        _implementation.main()
else:
    sys.modules[__name__] = _implementation
