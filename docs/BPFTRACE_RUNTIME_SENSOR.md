# TraceGate-R targeted bpftrace runtime sensor (LinuxONE/s390x)

## What it captures

`scripts/tracegate_bpftrace_collector.py` uses the host's existing `bpftrace` syscall tracepoints and a PID filter to collect one bounded observation window for a process owned by the current Linux user. It reads `/proc/<pid>/io` counters before and after the window, counts the target's file descriptors, and matches socket inode links to `/proc/<pid>/net/tcp` and `tcp6` to identify TCP tuples. The event is submitted to the local TraceGate-R API and checked for presence in the audit endpoint.

Observed absolute paths from `open`, `openat`, `openat2`, and `creat` probes are classified in memory only. Raw pathnames, raw syscall IDs, and endpoint addresses are not included in the console summary or written by this collector to a file. The API receives numeric feature counts, evidence states, and a package reference.

## Run it

From LinuxONE, identify the PID of a process you own (for example, use `ps -u "$USER" -o pid,comm,args` and verify the chosen PID with `ps -p 12345 -o pid,comm,args`). Then run the capture below, replacing `12345` with that PID. The latest deployment keeps the active app in `/home/linux1/tracegate-live/tracegate-r-offline-03639843ed`; if a later deployment changes the release directory, update `APP` to the release shown in the running Uvicorn command.

```bash
APP=/home/linux1/tracegate-live/tracegate-r-offline-03639843ed
/home/linux1/tracegate-live/venv/bin/python "$APP/scripts/tracegate_bpftrace_collector.py" --pid 12345 --duration 10 --interval 0.5
```

The collector requires `/usr/bin/bpftrace`, kernel syscall tracepoints, and passwordless `sudo -n bpftrace` access. The implementation uses the modern `args.field` bpftrace syntax documented by the [bpftrace one-liner reference](https://github.com/bpftrace/bpftrace/blob/master/docs/tutorial_one_liners.md); the deployment verifies probe fields before touching deployed files. It refuses to trace a process that does not belong to the collector's current UID, refuses an unsupported raw syscall tracepoint, checks that the PID's start time did not change, and caps each run at 120 seconds.

## What is deliberately left unknown

The following features remain `null` because a generic runtime PID cannot establish the dataset's package-install dependency graph or reproduce the precise trace aggregation used by QUT-DV25: `Install__Total_Dependency_Count`, `Install__Direct_Dependency_Count`, `Install__Indirect_Dependency_Count`, Filetop transfer units derived from the reference extractor, and `TCP__Unique_C-COMM`. Path totals require all four path probes, syscall group totals require every named probe in their group, and miscellaneous counts require all selected named syscall probes. The open-error total also requires all matching exit probes. TCP features remain `null` when a descriptor or socket table cannot be read completely. A null feature is not silently converted into an observed zero.


The event contains `QUT_DV25_FEATURE_EXTRACTION_PARITY_NOT_VALIDATED`; therefore, the model score is provisional and the evidence gate should retain `REVIEW_REQUIRED`. The named syscall groups capture genuine syscalls for the target PID but are not claimed to reproduce all dataset-specific grouping rules or package-install time windows. The in-memory stdout queue and path-event list are bounded; overflow discards the sample before submission. This collector captures real kernel observations, but it is not yet a validated drop-in replacement for the original QUT-DV25 trace-extraction pipeline. Do not use a partial vector to make a definitive malware claim. Full package-level monitoring still requires an isolated execution workflow, install trace collection, and benchmark parity testing.

## Failure behavior

If BPF attachment fails, PID ownership changes, telemetry cannot be read, the API rejects the event, or the new event is absent from the audit endpoint, the command returns a non-zero exit code and prints a bounded diagnostic. It does not change the API process or its port.
