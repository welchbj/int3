import pytest

from int3.architecture import Architectures
from int3.errors import Int3ArgumentError
from int3.platform import Platform, Triple


def test_triple_instantiation():
    """Test basic Triple instantiation."""
    triple = Triple(arch=Architectures.x86_64.value, platform=Platform.Linux)

    assert triple.arch.name == "x86_64"
    assert triple.platform == Platform.Linux
    assert triple.arch_str == "x86_64"
    assert triple.vendor_str == "pc"
    assert triple.sys_str == "linux"
    assert triple.env_str == "unknown"
    assert str(triple) == "x86_64-pc-linux-unknown"


def test_triple_from_str_two_components():
    """Test parsing triples with 2 components (arch-sys)."""
    triple = Triple.from_str("x86_64-linux")
    assert triple.arch.name == "x86_64"
    assert triple.platform == Platform.Linux

    triple = Triple.from_str("i686-linux")
    assert triple.arch.name == "x86"
    assert triple.platform == Platform.Linux

    triple = Triple.from_str("arm-linux")
    assert triple.arch.name == "arm"
    assert triple.platform == Platform.Linux


def test_triple_from_str_three_components():
    """Test parsing triples with 3 components (arch-sys-env)."""
    triple = Triple.from_str("x86_64-linux-gnu")
    assert triple.arch.name == "x86_64"
    assert triple.platform == Platform.Linux

    triple = Triple.from_str("aarch64-linux-musl")
    assert triple.arch.name == "aarch64"
    assert triple.platform == Platform.Linux


def test_triple_from_str_four_components():
    """Test parsing triples with 4 components (arch-vendor-sys-env)."""
    triple = Triple.from_str("x86_64-pc-linux-gnu")
    assert triple.arch.name == "x86_64"
    assert triple.platform == Platform.Linux

    triple = Triple.from_str("i686-unknown-linux-musl")
    assert triple.arch.name == "x86"
    assert triple.platform == Platform.Linux


def test_triple_from_str_architecture_aliases():
    """Test that architecture aliases work correctly."""
    # x86 aliases
    assert Triple.from_str("i386-linux").arch.name == "x86"
    assert Triple.from_str("i686-linux").arch.name == "x86"

    # x86_64 aliases
    assert Triple.from_str("amd64-linux").arch.name == "x86_64"
    assert Triple.from_str("x64-linux").arch.name == "x86_64"

    # ARM aliases
    assert Triple.from_str("armv7-linux").arch.name == "arm"
    assert Triple.from_str("armhf-linux").arch.name == "arm"

    # Aarch64 aliases
    assert Triple.from_str("arm64-linux").arch.name == "aarch64"


def test_triple_from_str_platform_variations():
    """Test that platform string variations work correctly."""
    # Linux variations
    assert Triple.from_str("x86_64-linux").platform == Platform.Linux
    assert Triple.from_str("x86_64-linux-gnu").platform == Platform.Linux
    assert Triple.from_str("x86_64-linux-musl").platform == Platform.Linux
    assert Triple.from_str("x86_64-pc-linux-gnu").platform == Platform.Linux


def test_triple_from_str_invalid_component_count():
    """Test that invalid component counts raise errors."""
    with pytest.raises(Int3ArgumentError, match="must have 2-4 components"):
        Triple.from_str("x86_64")

    with pytest.raises(Int3ArgumentError, match="must have 2-4 components"):
        Triple.from_str("x86_64-pc-linux-gnu-extra")
