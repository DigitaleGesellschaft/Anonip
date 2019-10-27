import sys

import pytest


@pytest.fixture()
def backup_and_restore_sys_argv():
    old_sys_argv = sys.argv
    yield
    sys.argv = old_sys_argv
