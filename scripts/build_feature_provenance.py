"""Build the checked-in, ordered feature-provenance manifest.

The manifest records runtime implementation facts separately from the
unavailable training-time definitions. It deliberately does not assert feature
parity with QUT-DV25.
"""
import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "data" / "model_feature_names.json"
OUTPUT_PATH = ROOT / "data" / "feature_provenance.json"
SYSCALL_GROUPS = {
    "IO": ("IO_Operations", "Unique_IO_Operations"),
    "File": ("File_Operations", "Unique_File_Operations"),
    "Memory": ("Memory_Operations", "Unique_Memory_Operations"),
    "Network": ("Network_Operations", "Unique_Network_Operations"),
    "Process_Management": (
        "Process_Management_Operations", "Unique_Process_Management_Operations"
    ),
    "Time": ("Time_Operations", "Unique_Time_Operations"),
    "IPC": ("IPC_Operations", "Unique_IPC_Operations"),
    "Filesystem": ("Filesystem_Operations", "Unique_Filesystem_Operations"),
    "Security": ("Security_Operations", "Unique_Security_Operations"),
}


def _runtime_mapping(name):
    if name == "Filetop__Total_Reads":
        return {
            "source": "/proc/<pid>/io:syscr at capture start/end",
            "unit": "read syscall count",
            "aggregation_window": "bounded capture interval",
            "aggregation": "end counter minus start counter",
            "availability": "implemented proxy; exact training parity unvalidated",
            "required_context": "same owned PID and readable procfs snapshots",
        }
    if name == "Filetop__Total_Writes":
        return {
            "source": "/proc/<pid>/io:syscw at capture start/end",
            "unit": "write syscall count",
            "aggregation_window": "bounded capture interval",
            "aggregation": "end counter minus start counter",
            "availability": "implemented proxy; exact training parity unvalidated",
            "required_context": "same owned PID and readable procfs snapshots",
        }
    if name in {
        "Filetop__Total_Read_Data_Transfer",
        "Filetop__Total_Write_Data_Transfer",
    }:
        return {
            "source": None,
            "unit": None,
            "aggregation_window": None,
            "aggregation": None,
            "availability": "unavailable by design; rchar/wchar are not substituted without validated unit parity",
            "required_context": "validated training-time transfer definition and matching source",
        }
    if name.startswith("Install__"):
        return {
            "source": None,
            "unit": None,
            "aggregation_window": None,
            "aggregation": None,
            "availability": "unavailable; package installation/dependency graph is not observed by the PID-scoped runtime collector",
            "required_context": "package metadata and the original installation observation window",
        }
    if name == "Opensnoop__Total_Paths":
        return {
            "source": "PID-scoped open/openat/openat2/creat path events",
            "unit": "path event count; not distinct paths",
            "aggregation_window": "bounded bpftrace capture interval",
            "aggregation": "count of captured path events",
            "availability": "implemented proxy when all required path probes are available; parity unvalidated",
            "required_context": "owned PID, complete path probes, bounded event queue",
        }
    if name == "Opensnoop__Total_Error":
        return {
            "source": "PID-scoped open syscall exit probes with negative return values",
            "unit": "failed open event count",
            "aggregation_window": "bounded bpftrace capture interval",
            "aggregation": "count of captured failed-open events",
            "availability": "implemented proxy when exit probes are available; parity unvalidated",
            "required_context": "owned PID and complete supported open-exit probes",
        }
    if name == "Opensnoop__Total__File_Descriptor":
        return {
            "source": "final /proc/<pid>/fd snapshot",
            "unit": "currently open descriptor count",
            "aggregation_window": "point-in-time snapshot at capture end",
            "aggregation": "count of visible descriptor entries",
            "availability": "implemented snapshot proxy; not an event total and parity unvalidated",
            "required_context": "same owned PID and complete descriptor snapshot",
        }
    if name == "Opensnoop__Python_Related_Keywords":
        description = "count of captured paths containing configured Python-related keywords"
    elif name == "Opensnoop__Install_Package_Keywords":
        description = "count of captured paths containing configured package-install keywords"
    elif name.startswith("Opensnoop__"):
        bucket = name.removeprefix("Opensnoop__").replace("_DIR_Installation", "").replace("_Access", "").lower()
        description = f"count of captured paths classified into the {bucket!r} path bucket"
    else:
        description = None
    if description is not None:
        return {
            "source": "in-memory path classification of PID-scoped open events",
            "unit": "matching path event count",
            "aggregation_window": "bounded bpftrace capture interval",
            "aggregation": description,
            "availability": "implemented proxy when all required path probes are available; parity unvalidated",
            "required_context": "owned PID, complete path probes, path resolution; raw paths are not persisted",
        }
    if name == "SysCall__Total_System_Calls":
        return {
            "source": "PID-scoped raw sys_enter tracepoint",
            "unit": "syscall event count",
            "aggregation_window": "bounded bpftrace capture interval",
            "aggregation": "count of captured raw syscall events",
            "availability": "implemented when the raw tracepoint is available; parity unvalidated",
            "required_context": "owned PID and raw syscall tracepoint",
        }
    if name == "SysCall__Unique_System_Calls":
        return {
            "source": "numeric syscall IDs from the raw sys_enter tracepoint",
            "unit": "distinct raw syscall ID count",
            "aggregation_window": "bounded bpftrace capture interval",
            "aggregation": "cardinality of observed raw syscall IDs",
            "availability": "implemented when the raw tracepoint is available; parity unvalidated",
            "required_context": "owned PID and raw syscall tracepoint",
        }
    if name == "SysCall__Miscellaneous_Operations":
        return {
            "source": "raw syscall total minus calls assigned to the selected named groups",
            "unit": "estimated syscall event count",
            "aggregation_window": "bounded bpftrace capture interval",
            "aggregation": "remainder, only when every selected named probe is available",
            "availability": "implemented estimate; not training-parity validated",
            "required_context": "raw tracepoint and complete selected named syscall probes",
        }
    if name == "SysCall__Unique_Miscellaneous_Operations":
        return {
            "source": "raw syscall IDs not mapped to selected named syscall probes",
            "unit": "distinct raw syscall ID count",
            "aggregation_window": "bounded bpftrace capture interval",
            "aggregation": "cardinality of unmapped IDs, only with complete named probes",
            "availability": "implemented estimate; not training-parity validated",
            "required_context": "raw tracepoint and complete selected named syscall probes",
        }
    for group, (total_suffix, unique_suffix) in SYSCALL_GROUPS.items():
        if name == f"SysCall__{total_suffix}":
            return {
                "source": f"PID-scoped named syscall probes in the {group} group",
                "unit": "syscall event count",
                "aggregation_window": "bounded bpftrace capture interval",
                "aggregation": "sum of observed group members, only when all group probes attach",
                "availability": "implemented when group probe coverage is complete; parity unvalidated",
                "required_context": "owned PID and all selected probes for this group",
            }
        if name == f"SysCall__{unique_suffix}":
            return {
                "source": f"PID-scoped named syscall probes in the {group} group",
                "unit": "distinct observed syscall name count",
                "aggregation_window": "bounded bpftrace capture interval",
                "aggregation": "cardinality of observed group members, only with complete group probes",
                "availability": "implemented when group probe coverage is complete; parity unvalidated",
                "required_context": "owned PID and all selected probes for this group",
            }
    if name == "TCP__Unique_C-COMM":
        return {
            "source": None,
            "unit": None,
            "aggregation_window": None,
            "aggregation": None,
            "availability": "unavailable by design; source meaning and parity are not established",
            "required_context": "validated definition and a matching process-communication source",
        }
    if name == "TCP__Python_Related_Process":
        return {
            "source": "process comm/cmdline keyword check plus associated TCP socket rows",
            "unit": "binary indicator (0 or 1)",
            "aggregation_window": "capture-window socket-table observations",
            "aggregation": "1 when process text contains 'python' and a matching TCP row exists",
            "availability": "implemented heuristic proxy; parity unvalidated",
            "required_context": "owned PID, readable process metadata, complete descriptor/socket snapshots",
        }
    if name == "TCP__Total_Entries":
        return {
            "source": "associated /proc/<pid>/net/tcp and tcp6 rows",
            "unit": "distinct observed socket row count",
            "aggregation_window": "union of complete snapshots during capture",
            "aggregation": "cardinality of observed local/remote endpoints and state",
            "availability": "implemented when descriptor and TCP snapshots are complete; parity unvalidated",
            "required_context": "owned PID, readable descriptors and complete TCP tables",
        }
    if name.startswith("TCP__Local_IP_"):
        field = 0
        description = "distinct local IP address count"
    elif name.startswith("TCP__Remote_IP_"):
        field = 2
        description = "distinct remote IP address count"
    elif name.startswith("TCP__Local_Port_"):
        field = 1
        description = "distinct local port count"
    elif name.startswith("TCP__Remote_Port_"):
        field = 3
        description = "distinct remote port count"
    else:
        raise ValueError(f"No runtime mapping declared for {name!r}")
    return {
        "source": "associated /proc/<pid>/net/tcp and tcp6 rows",
        "unit": "distinct endpoint field count",
        "aggregation_window": "union of complete snapshots during capture",
        "aggregation": description,
        "availability": "implemented when descriptor and TCP snapshots are complete; parity unvalidated",
        "required_context": "owned PID, readable descriptors and complete TCP tables",
    }


def build_manifest():
    schema_bytes = SCHEMA_PATH.read_bytes()
    names = json.loads(schema_bytes)
    if len(names) != 48 or len(set(names)) != 48:
        raise ValueError("The release schema must contain 48 unique ordered feature names.")
    features = []
    for name in names:
        features.append({
            "name": name,
            "meaning": "Training-time meaning is unverified; this wording records only the implemented runtime mapping.",
            "training": {
                "source_reference": "QUT-DV25 processed trace columns referenced by scripts/replay_qut.py",
                "definition": None,
                "unit": None,
                "aggregation_window": None,
                "transformation": None,
                "validation_status": "BLOCKED_SOURCE_ARCHIVE_AND_TRAINING_PIPELINE_UNAVAILABLE_IN_CHECKOUT",
            },
            "runtime": _runtime_mapping(name),
            "parity_status": "NOT_VALIDATED",
            "missing_value_semantics": "null means the runtime source was unavailable, incomplete, or unsupported; it is never a measured zero.",
        })
    return {
        "schema_file": "data/model_feature_names.json",
        "schema_sha256": hashlib.sha256(schema_bytes).hexdigest(),
        "feature_count": len(names),
        "feature_order": names,
        "training_data_status": "QUT-DV25 archive is referenced at the local path in scripts/replay_qut.py but is not included in this checkout.",
        "runtime_feature_parity": "NOT_VALIDATED",
        "features": features,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the checked-in manifest is stale")
    args = parser.parse_args()
    rendered = json.dumps(build_manifest(), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if not OUTPUT_PATH.is_file() or OUTPUT_PATH.read_text(encoding="utf-8") != rendered:
            raise SystemExit("Feature provenance manifest is missing or stale; regenerate it from reviewed mappings.")
        print("Feature provenance manifest is current.")
        return
    OUTPUT_PATH.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"Wrote {OUTPUT_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
