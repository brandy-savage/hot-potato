from pathlib import Path
import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def clean_text():
    return (FIXTURES / "clean.txt").read_text()


@pytest.fixture
def inject_basic():
    return (FIXTURES / "inject_basic.txt").read_text()


@pytest.fixture
def inject_b64():
    return (FIXTURES / "inject_b64.txt").read_text()


@pytest.fixture
def inject_morse():
    return (FIXTURES / "inject_morse.txt").read_text()


@pytest.fixture
def inject_wallet():
    return (FIXTURES / "inject_wallet.txt").read_text()
