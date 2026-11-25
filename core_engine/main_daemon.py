"""Compatibility entry point for the specification's ``core_engine`` path."""
# Delegates CLI orchestration and daemon lifecycle to engine.main_daemon.

from engine.main_daemon import *
from engine.main_daemon import main

if __name__ == "__main__":
    main()
