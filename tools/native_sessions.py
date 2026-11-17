"""Pure configuration/argv helpers for bounded native F-Stack TCP sessions.

The launcher owns device checks, private directory creation and process lifetime.
This module performs no file I/O, network operations or process execution.
The INI keys match F-Stack v1.25 (761639943bdda33103aa98241ca6a3079f1c1b7e).
"""
from __future__ import annotations

from dataclasses import replace
import os
from pathlib import PurePosixPath
import re

from wizard_inputs import LAB_SESSION_ROLES, SessionConfig


_PCI = re.compile(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]\Z", re.ASCII)
_PREFIX = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}\Z", re.ASCII)


def validate_lab_role(config: SessionConfig, hostname: str) -> None:
    """Reject the opposite TCP role on either known lab VM before native I/O.

    The launcher supplies the machine's hostname. Unknown machines retain an
    explicit role choice so this pure helper remains portable to other labs.
    """
    if not isinstance(config, SessionConfig):
        raise ValueError("TCP session configuration must be a SessionConfig")
    if not isinstance(hostname, str):
        raise ValueError("The launcher must provide its hostname")
    expected = LAB_SESSION_ROLES.get(hostname)
    if expected is not None and config.role != expected:
        vm = "VM 104" if expected == "client" else "VM 105"
        raise ValueError(f"{hostname} is {vm}; complete TCP must run as {expected} here. "
                         "Start the server on VM 105 and the client on VM 104.")


def _validated(config):
    if not isinstance(config, SessionConfig):
        raise ValueError("TCP session configuration must be a SessionConfig")
    config.validate()
    # The pinned F-Stack version parses at most 128 lcore-mask bits. Do not
    # silently truncate a selected CPU to a different enabled lcore.
    if type(config.core) is not int or not 0 <= config.core < 128:
        raise ValueError("Native TCP CPU ID must be an integer from 0 to 127")
    if not isinstance(config.pci, str) or not _PCI.fullmatch(config.pci):
        raise ValueError("Native TCP needs exactly one full PCI address")
    if int(config.pci.split(":")[2].split(".")[0], 16) > 31:
        raise ValueError("PCI device number must be from 00 to 1f")
    if (config.local_ip, config.peer_ip) not in (
            ("198.18.0.1", "198.18.0.2"), ("198.18.0.2", "198.18.0.1")):
        raise ValueError("Native TCP sessions require the exact VM104/VM105 lab IP pair")
    return config


def _path(value, label):
    try:
        text = os.fspath(value)
    except TypeError as error:
        raise ValueError(f"{label} must be an absolute POSIX path") from error
    if not isinstance(text, str) or not text or len(text) > 4095:
        raise ValueError(f"{label} must be a nonempty path of at most 4095 characters")
    if (not text.startswith("/") or text == "/" or text.endswith("/") or
            any(ord(char) < 32 or ord(char) == 127 for char in text) or
            "\\" in text or any(part in ("", ".", "..") for part in text.split("/")[1:])):
        raise ValueError(f"{label} must be an absolute POSIX path without traversal or control characters")
    # Do not call resolve()/absolute(): these helpers must not inspect the host.
    return text


def _stack_configuration(config: SessionConfig, sessiondir, cores) -> str:
    config = _validated(config)
    directory = _path(sessiondir, "Session directory")
    basename = PurePosixPath(directory).name
    if not _PREFIX.fullmatch(basename):
        raise ValueError("Session directory basename must contain 1..48 ASCII letters, digits, _ or -")
    prefix = "pg-tcp-" + basename
    core_mask = sum(1 << core for core in cores)
    # The same high mapping hint is used by all processes, while ASLR stays
    # enabled. EAL still validates that a secondary can reproduce the mapping.
    shared_base = "base_virtaddr=0x200000000000\n" if len(cores) > 1 else ""
    # tx_csum_offoad_skip is the upstream option's intentional spelling.
    return (
        "[dpdk]\n"
        f"lcore_mask={core_mask:x}\n"
        "channel=4\n"
        f"memory={config.memory_mib}\n"
        f"file_prefix={prefix}\n"
        f"{shared_base}"
        f"allow={config.pci.lower()}\n"
        "port_list=0\n"
        "promiscuous=0\n"
        "numa_on=0\n"
        "tso=0\n"
        "tx_csum_offoad_skip=1\n"
        "pkt_tx_delay=0\n"
        "idle_sleep=0\n\n"
        "[pcap]\n"
        "enable=0\n\n"
        "[port0]\n"
        f"addr={config.local_ip}\n"
        "netmask=255.255.255.252\n"
        "broadcast=198.18.0.3\n"
        f"gateway={config.peer_ip}\n"
        f"lcore_list={','.join(str(core) for core in cores)}\n\n"
        "[freebsd.boot]\n"
        "hz=100\n"
        "fd_reserve=1024\n"
        "kern.ipc.maxsockets=4096\n"
        "net.inet.tcp.tcbhashsize=4096\n"
        "kern.ncallout=8192\n\n"
        "[freebsd.sysctl]\n"
        "kern.ipc.somaxconn=1024\n"
        "net.inet.tcp.msl=2000\n"
        "net.inet.ip.forwarding=0\n"
        "net.inet.ip.redirect=0\n"
    )


def stack_configuration(config: SessionConfig, sessiondir) -> str:
    """Return the original single-NIC/single-lcore configuration."""
    config = _validated(config)
    if len(config.worker_cores) != 1:
        raise ValueError("Multiple TCP workers require worker_stack_configuration")
    return _stack_configuration(config, sessiondir, config.worker_cores)


def worker_stack_configuration(config: SessionConfig, sessiondir) -> str:
    """Return one shared INI for primary and secondary F-Stack processes.

    The complete CPU mask describes the process group. F-Stack maps proc-id to
    one CPU and that CPU's index in lcore_list identifies its RX/TX queue.
    Memory is the group-wide hugepage budget, not a separate budget per worker.
    Up to eight software workers are supported. The caller must independently
    verify that the selected NIC and virtual path support that many queues;
    selecting eight CPU IDs does not establish eight-queue NIC capability.
    """
    config = _validated(config)
    return _stack_configuration(config, sessiondir, config.worker_cores)


def session_command(binary, config: SessionConfig, ini, stats, live) -> list[str]:
    """Return an argv list; F-Stack arguments precede the app's -- separator."""
    config = _validated(config)
    executable = _path(binary, "F-Stack executable")
    configuration = _path(ini, "F-Stack INI")
    statistics = _path(stats, "Statistics file")
    live_statistics = _path(live, "Live statistics file")
    if len({executable, configuration, statistics, live_statistics}) != 4:
        raise ValueError("Executable, INI, final report and live report paths must be distinct")
    command = [executable, f"--conf={configuration}", "--proc-type=primary", "--proc-id=0", "--",
            "--role", config.role, "--local-ip", config.local_ip, "--peer-ip", config.peer_ip,
            "--port", str(config.port), "--connections", str(config.connections),
            "--concurrency", str(config.concurrency), "--cps", "0" if config.cps is None else str(config.cps),
            "--duration-s", str(config.duration_seconds), "--timeout-s", str(config.timeout_seconds),
            "--payload-size", str(config.payload),
            "--ttl-min", str(config.ttl_min), "--ttl-max", str(config.ttl_max), "--stats-json", statistics,
            "--live-json", live_statistics]
    if config.software_dispatch:
        command += ["--software-dispatch", "1"]
    return command


def _partition(total: int, workers: int, index: int) -> int:
    quotient, remainder = divmod(total, workers)
    return quotient + (index < remainder)


def worker_session_command(binary, config: SessionConfig, ini, stats, live, index,
                           coordinated=True) -> list[str]:
    """Build one worker's argv from global rate/quota/concurrency settings.

    Global integers are divided by quotient plus a remainder assigned to the
    first workers, so the sum is exact. None preserves explicitly unpaced CPS.
    Coordinated workers wait for their owner's start signal and keep the stack
    alive at quiescence; the owner must stop secondaries before the primary.
    """
    config = _validated(config)
    workers = len(config.worker_cores)
    if type(index) is not int or not 0 <= index < workers:
        raise ValueError("TCP worker index must identify one selected CPU")
    if type(coordinated) is not bool or workers > 1 and not coordinated:
        raise ValueError("Multiple TCP workers require coordinated process lifetime")
    cps = None if config.cps is None else _partition(config.cps, workers, index)
    local = replace(config, core=config.worker_cores[index], cores=None,
                    connections=_partition(config.connections, workers, index),
                    concurrency=_partition(config.concurrency, workers, index), cps=cps)
    result = session_command(binary, local, ini, stats, live)
    result[2] = "--proc-type=" + ("primary" if index == 0 else "secondary")
    result[3] = "--proc-id=" + str(index)
    result += ["--worker-index", str(index), "--worker-count", str(workers),
               "--coordinated", "1" if coordinated else "0"]
    return result
