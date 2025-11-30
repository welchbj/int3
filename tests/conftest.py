"""Pytest configuration and fixtures for int3 tests."""

import pytest

from int3.factor import compute_factor


@pytest.fixture(scope="session", autouse=True)
def clear_cache_at_start():
    """Clear cache at the start of the test session for consistent results."""
    compute_factor.cache_clear()

    yield


def pytest_terminal_summary(
    terminalreporter: pytest.TerminalReporter,
    exitstatus: pytest.ExitCode,
    config: pytest.Config,
) -> None:
    """Add cache statistics to the pytest terminal summary."""
    cache_info = compute_factor.cache_info()
    total_calls = cache_info.hits + cache_info.misses

    if total_calls <= 0:
        return

    hit_rate = cache_info.hits / total_calls * 100
    terminalreporter.section("compute_factor() Cache Statistics")
    terminalreporter.write_line(f"Total calls  : {total_calls}")
    terminalreporter.write_line(f"Cache hits   : {cache_info.hits} ({hit_rate:.1f}%)")
    terminalreporter.write_line(f"Cache misses : {cache_info.misses}")
    terminalreporter.write_line(
        f"Cache size   : {cache_info.currsize}/{cache_info.maxsize}"
    )
    terminalreporter.write_line(
        f"Performance  : Avoided {cache_info.hits} redundant SAT solver calls"
    )
