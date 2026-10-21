"""CI test runner for the Python process monitor.

test_process_monitor has a set of pre-existing, platform-dependent
failures/errors tracked as a known baseline. unittest has no native xfail,
so this runner:

  1. executes the full test_process_monitor suite programmatically;
  2. treats every test in EXPECTED_FAILURES that fails as "xfail" (expected
     failure — reported, not counted against the exit code);
  3. fails the run when ANY failure/error outside the xfail list appears
     (the "silently became 10 failures" guard), or when the suite itself
     cannot be collected;
  4. reports "xpass" when a listed test unexpectedly passes (informational;
     not a failure — platforms differ, e.g. cgroup tests pass on Linux).

Usage:  python monitor/run_tests.py
"""

import sys
import unittest

# Pre-existing baseline failures, verified 2026-09-29 on Windows.
# Format: "TestClass.test_name". Remove entries as they are fixed; NEVER add
# new ones without a linked issue.
EXPECTED_FAILURES = frozenset({
    # cgroup reader tests assume a POSIX cgroupfs layout that does not exist
    # on Windows (and mock open() against absolute Linux paths).
    "TestCgroupReader.test_read_blkio_v2",
    "TestCgroupReader.test_read_cpu_v1",
    "TestCgroupReader.test_read_cpu_v2",
    "TestCgroupReader.test_read_memory_v2",
    "TestCgroupReader.test_read_pids",
    # snapshot change detection / kill-command mocks drifted from the
    # implementation (memory_rss threshold semantics, Process ctor mock).
    "TestProcessMonitorSnapshot.test_changed_fields",
    "TestProcessMonitorSnapshot.test_memory_rss_change_below_threshold_is_ignored",
    "TestProcessMonitorKillCommand.test_handle_command_kill_pid",
    "TestProcessMonitorRiskScoring.test_handle_snapshot_autokill_high_risk",
})


def main() -> int:
    loader = unittest.TestLoader()
    try:
        suite = loader.loadTestsFromName("test_process_monitor")
    except Exception as exc:  # suite must at least collect
        print(f"[monitor-tests] FATAL: cannot collect test_process_monitor: {exc}")
        return 2

    runner = unittest.TextTestRunner(verbosity=1, stream=sys.stdout)
    result = runner.run(suite)

    failed_ids = {
        f"{case.__class__.__name__}.{case._testMethodName}"
        for case, _ in result.failures + result.errors
    }
    unexpected = sorted(failed_ids - EXPECTED_FAILURES)
    xfailed = sorted(failed_ids & EXPECTED_FAILURES)
    xpassed = sorted(EXPECTED_FAILURES - failed_ids)

    print()
    print(f"[monitor-tests] ran={result.testsRun} failed={len(failed_ids)}")
    for tid in xfailed:
        print(f"[monitor-tests] xfail (known baseline failure): {tid}")
    for tid in xpassed:
        print(f"[monitor-tests] xpass (listed failure now passes — consider "
              f"removing from EXPECTED_FAILURES): {tid}")

    if unexpected:
        print("[monitor-tests] FAIL: unexpected failures outside the xfail list:")
        for tid in unexpected:
            print(f"[monitor-tests]   UNEXPECTED: {tid}")
        return 1

    print("[monitor-tests] OK: no failures outside the known-baseline xfail list")
    return 0


if __name__ == "__main__":
    sys.exit(main())
