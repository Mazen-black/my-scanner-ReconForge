"""Compatibility entry point; implementation lives in reconforge.assessment."""
import importlib
import sys

_implementation = importlib.import_module("reconforge.assessment")

if __name__ == "__main__":
    if hasattr(_implementation, "main"):
        _implementation.main()
else:
    sys.modules[__name__] = _implementation
