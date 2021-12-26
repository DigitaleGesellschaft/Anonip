import logging
import sys

import pytest


@pytest.fixture()
def backup_and_restore_sys_argv():
    old_sys_argv = sys.argv
    yield
    sys.argv = old_sys_argv


@pytest.fixture()
def enable_logging():
    logging.disable(logging.NOTSET)
    logging.getLogger("anonip").setLevel(logging.CRITICAL)
    yield
    logging.disable(logging.CRITICAL)
