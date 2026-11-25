"""Compatibility entry point; implementation lives in reconforge.scanner."""
import importlib
import sys

_implementation = importlib.import_module("reconforge.scanner")

if __name__ == "__main__":
    if hasattr(_implementation, "main"):
        _implementation.main()
else:
    sys.modules[__name__] = _implementation
