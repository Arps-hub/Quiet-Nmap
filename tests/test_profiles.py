"""Tests for scan profiles."""

from quietnmap.models import ScanConfig, ScanType
from quietnmap.profiles import apply_profile, list_profiles, PROFILES


def test_list_profiles():
    profiles = list_profiles()
    assert len(profiles) >= 5
    names = [p.name for p in profiles]
    assert "quiet" in names
    assert "normal" in names
    assert "aggressive" in names
    assert "paranoid" in names
    assert "quick" in names


def test_apply_quiet_profile():
    config = ScanConfig(targets=["10.0.0.1"])
    config = apply_profile(config, "quiet")
    assert config.max_concurrency == 50
    assert config.delay_ms == 100.0
    assert config.detect_services is False


def test_apply_aggressive_profile():
    config = ScanConfig(targets=["10.0.0.1"])
    config = apply_profile(config, "aggressive")
    assert config.max_concurrency == 2000
    assert config.detect_services is True
    assert config.detect_os is True


def test_apply_invalid_profile():
    config = ScanConfig(targets=["10.0.0.1"])
    try:
        apply_profile(config, "nonexistent")
        assert False, "Should raise ValueError"
    except ValueError as e:
        assert "nonexistent" in str(e)


def test_quick_profile_ports():
    config = ScanConfig(targets=["10.0.0.1"])
    config = apply_profile(config, "quick")
    assert len(config.ports) > 0
    assert 80 in config.ports
    assert 22 in config.ports
