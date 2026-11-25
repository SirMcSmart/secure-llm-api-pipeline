import pytest

from redteam_lib import hardened, vulnerable


@pytest.fixture
def hard():
    return hardened()


@pytest.fixture(scope="module")
def vuln():
    return vulnerable()
