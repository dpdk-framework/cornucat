"""Terminal questions for CornuCat's interactive launcher.

This module only gathers and validates values. It does not open files, start
processes, access a network, or change a device. Input cancellation deliberately
propagates to the launcher so EOF and Ctrl+C can share its cleanup path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, localcontext
import re

UINT64_MAX = (1 << 64) - 1
UINT32_MAX = (1 << 32) - 1
MAX_PPS = 1_000_000_000
MAX_SESSION_CPS = 1_000_000_000
MAX_SESSION_CONCURRENCY = 1024
MAX_SESSION_WORKERS = 8
LAB_SESSION_ROLES = {"dpdk-review-ubuntu": "client", "dpdk-receiver-ubuntu": "server"}
MAX_STREAMS = 16
NAME = re.compile(r"[A-Za-z0-9_-]{1,31}\Z", re.ASCII)
INTEGER = re.compile(r"[0-9]+\Z", re.ASCII)
DECIMAL = re.compile(r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)\Z", re.ASCII)
PCI = re.compile(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]\Z", re.ASCII)
MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z", re.ASCII)
PROTOCOLS = ("udp", "tcp", "icmp")
PROTOCOL_LABELS = ("UDP", "TCP", "ICMP echo request")
TCP_PROFILES = ("syn", "ack", "syn-ack", "psh-ack", "fin-ack", "rst", "rst-ack")
TCP_PROFILE_LABELS = ("SYN", "ACK", "SYN + ACK", "PSH + ACK", "FIN + ACK", "RST", "RST + ACK")


class SessionRequested(Exception):
    """Configuration-time request to replace raw streams with TCP sessions."""


def _integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{label} must be an integer from {low:,} to {high:,}")
    return value


def lab_ip(text):
    """Accept exactly the RFC1918 and 198.18.0.0/15 ranges used by C options."""
    if not isinstance(text, str):
        raise ValueError("Enter an IPv4 address in an RFC1918 or 198.18.0.0/15 lab range")
    parts = text.split(".")
    if len(parts) != 4 or any(not INTEGER.fullmatch(part) or len(part) > 3 for part in parts):
        raise ValueError("Enter an IPv4 address with four decimal octets")
    octets = tuple(int(part) for part in parts)
    if any(part > 255 for part in octets):
        raise ValueError("Each IPv4 octet must be from 0 to 255")
    a, b, _c, _d = octets
    if not (a == 10 or a == 172 and 16 <= b <= 31 or a == 192 and b == 168
            or a == 198 and b in (18, 19)):
        raise ValueError("Use an RFC1918 or 198.18.0.0/15 lab IPv4 address")
    return ".".join(str(part) for part in octets)


def unicast_mac(text):
    if not isinstance(text, str) or not MAC.fullmatch(text):
        raise ValueError("Enter six hexadecimal MAC octets separated by colons")
    octets = bytes(int(part, 16) for part in text.split(":"))
    if not any(octets) or octets[0] & 1:
        raise ValueError("Destination MAC must be a nonzero unicast address")
    return text.lower()


@dataclass
class Stream:
    name: str
    protocol: str
    pps: int | None
    count: int
    ttl_min: int
    ttl_max: int
    payload: int
    seed: int
    paused: bool = False
    tcp_flags: str = "syn"
    tcp_ack: int = 0

    def spec(self):
        """Return one strict C stream specification, without shell quoting."""
        if not isinstance(self.name, str) or not NAME.fullmatch(self.name):
            raise ValueError("Stream name must contain 1..31 ASCII letters, digits, _ or -")
        if self.protocol not in PROTOCOLS:
            raise ValueError("Stream protocol must be udp, tcp or icmp")
        if self.pps is not None:
            _integer(self.pps, 1, MAX_PPS, "Packet rate")
        _integer(self.count, 1, UINT64_MAX, "Packet count")
        _integer(self.ttl_min, 1, 255, "Minimum TTL")
        _integer(self.ttl_max, self.ttl_min, 255, "Maximum TTL")
        _integer(self.payload, 0, 1400, "Payload size")
        _integer(self.seed, 1, UINT64_MAX, "Random seed")
        if type(self.paused) is not bool:
            raise ValueError("Paused must be true or false")
        if self.tcp_flags not in TCP_PROFILES:
            raise ValueError("Choose one of the supported raw TCP flag profiles")
        _integer(self.tcp_ack, 0, UINT32_MAX, "TCP acknowledgment number")
        if self.protocol != "tcp" and (self.tcp_flags != "syn" or self.tcp_ack != 0):
            raise ValueError("TCP flag and acknowledgment settings require TCP")
        if self.tcp_ack and "ack" not in self.tcp_flags:
            raise ValueError("A nonzero TCP acknowledgment requires a profile with ACK")
        rate = "unlimited=1" if self.pps is None else f"pps={self.pps}"
        tcp = f",tcp-flags={self.tcp_flags},tcp-ack={self.tcp_ack}" if self.protocol == "tcp" else ""
        return (f"name={self.name},protocol={self.protocol},{rate},count={self.count},"
                f"payload={self.payload},ttl-min={self.ttl_min},ttl-max={self.ttl_max},"
                f"seed={self.seed},pause={int(self.paused)}{tcp}")


@dataclass
class SessionConfig:
    role: str = "client"
    pci: str = "0000:00:13.0"
    core: int = 0
    memory_mib: int = 512
    port: int = 9000
    connections: int = 200
    concurrency: int = 16
    cps: int | None = 100
    duration_seconds: int | None = None
    timeout_seconds: int = 5
    payload: int = 64
    cores: tuple[int, ...] | None = None
    software_dispatch: bool = False
    ttl_min: int = 64
    ttl_max: int = 64

    def __post_init__(self):
        if self.duration_seconds is None:
            self.duration_seconds = 300 if self.role == "server" else 30

    @property
    def worker_cores(self):
        return (self.core,) if self.cores is None else self.cores

    @property
    def local_ip(self):
        return "198.18.0.1" if self.role == "client" else "198.18.0.2"

    @property
    def peer_ip(self):
        return "198.18.0.2" if self.role == "client" else "198.18.0.1"

    @property
    def local_mac(self):
        return "02:00:00:68:00:01" if self.role == "client" else "02:00:00:69:00:02"

    @property
    def peer_mac(self):
        return "02:00:00:69:00:02" if self.role == "client" else "02:00:00:68:00:01"

    def validate(self):
        if self.role not in ("client", "server"):
            raise ValueError("TCP session role must be client or server")
        if type(self.software_dispatch) is not bool:
            raise ValueError("TCP software dispatch must be a boolean")
        _integer(self.ttl_min, 1, 255, "Minimum TCP IPv4 TTL")
        _integer(self.ttl_max, self.ttl_min, 255, "Maximum TCP IPv4 TTL")
        if not isinstance(self.pci, str) or not PCI.fullmatch(self.pci):
            raise ValueError("TCP session NIC must use a full PCI address")
        _integer(self.connections, 1, UINT32_MAX, "Connection count")
        if self.cps is not None:
            _integer(self.cps, 1, MAX_SESSION_CPS, "Client connection attempts per second")
        cores = self.worker_cores
        if not isinstance(cores, tuple) or not 1 <= len(cores) <= MAX_SESSION_WORKERS:
            raise ValueError("TCP worker cores must be a tuple containing 1..8 CPU IDs")
        for core in cores:
            _integer(core, 0, 127, "TCP worker CPU ID")
        if len(set(cores)) != len(cores) or tuple(sorted(cores)) != cores or cores[0] != self.core:
            raise ValueError("TCP worker CPU IDs must be unique, ascending, and start with the selected CPU ID")
        workers = len(cores)
        for value, low, high, label in (
                (self.core, 0, 127, "DPDK CPU ID"),
                (self.memory_mib, 64, 65536, "DPDK memory"),
                (self.port, 1024, 65535, "TCP port"),
                (self.concurrency, 1, min(MAX_SESSION_CONCURRENCY, self.connections), "Concurrent connections"),
                (self.duration_seconds, 1, 3600, "Duration in seconds"),
                (self.timeout_seconds, 1, 30, "Connection timeout in seconds"),
                (self.payload, 1, 1400, "TCP payload bytes")):
            _integer(value, low, high, label)
        if self.connections < workers or self.concurrency < workers:
            raise ValueError("The global TCP quota and concurrency must each allow at least one connection per worker")
        if self.cps is not None and self.cps < workers:
            raise ValueError("A positive global TCP rate must allow at least one attempt/s per worker; choose max to remove pacing")
        return self


def replay_path(text):
    if not isinstance(text, str) or not text or len(text) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError("Enter a PCAP file path of 1..4096 characters without control characters")
    return text


@dataclass
class ReplayConfig:
    path: str
    loops: int = 1
    original_timing: bool = False
    count: int | None = None
    pps: int | None = 1000
    ttl: int | None = None

    def validate(self):
        replay_path(self.path)
        _integer(self.loops, 0, 10000, "Replay loops")
        if type(self.original_timing) is not bool:
            raise ValueError("Original capture timing must be true or false")
        if self.count is not None:
            _integer(self.count, 1, UINT64_MAX, "Replay packet limit")
        if self.pps is not None:
            _integer(self.pps, 1, MAX_PPS, "Replay packet rate")
        if self.original_timing and self.pps is not None:
            raise ValueError("Choose original capture timing or a fixed packet rate")
        if self.ttl is not None:
            _integer(self.ttl, 1, 255, "Replay IPv4 TTL")
        return self


@dataclass
class Config:
    pci: str
    core: int
    memory_mib: int = 512
    src_ip: str = "198.18.0.1"
    dst_ip: str = "198.18.0.2"
    dst_mac: str = "02:00:00:69:00:02"
    src_port: int = 49152
    dst_port: int = 9000
    burst: int = 128
    tx_descriptors: int = 1024
    template: str = "static"
    duration_ms: int = 0
    streams: list[Stream] = field(default_factory=list)
    mode: str = "streams"
    session: SessionConfig | None = None
    replay: ReplayConfig | None = None


class Prompt:
    def __init__(self, read=input, write=print, *, hostname=None):
        if hostname is not None and not isinstance(hostname, str):
            raise ValueError("Hostname must be text when provided by the launcher")
        self.read = read
        self.write = write
        self.hostname = hostname
        self._next_seed = 1

    def choice(self, label, options, default=1):
        if not options:
            raise ValueError("A menu needs at least one option")
        _integer(default, 1, len(options), "Default choice")
        self.write(label)
        for index, option in enumerate(options, 1):
            self.write(f"  {index}. {option}" + (" [default]" if index == default else ""))
        while True:
            answer = self.read(f"Choice [{default}]: ").strip()
            if not answer:
                return default
            if len(answer) <= 20 and INTEGER.fullmatch(answer):
                value = int(answer)
                if 1 <= value <= len(options):
                    return value
            self.write(f"Choose a number from 1 to {len(options)}.")

    def integer(self, label, low, high, default=None):
        if type(low) is not int or type(high) is not int or low > high:
            raise ValueError("Invalid integer range")
        if default is not None:
            _integer(default, low, high, "Default value")
        suffix = f" [{default}]" if default is not None else ""
        while True:
            answer = self.read(f"{label}{suffix}: ").strip()
            if not answer and default is not None:
                return default
            if len(answer) <= 32 and INTEGER.fullmatch(answer):
                value = int(answer)
                if low <= value <= high:
                    return value
            self.write(f"Enter a whole number from {low:,} to {high:,} using decimal digits.")

    def rate(self, default=1_000_000):
        if default is not None:
            _integer(default, 1, MAX_PPS, "Default packet rate")
        default_unit = 4 if default is None else 3 if default >= 1_000_000 else 2 if default >= 1000 else 1
        unit = self.choice("Sending rate", ["Packets per second (pps)", "Thousands per second (kpps)",
                                           "Millions per second (Mpps)", "Maximum available speed"], default_unit)
        if unit == 4:
            return None
        multiplier = (1, 1000, 1_000_000)[unit - 1]
        with localcontext() as context:
            context.prec = 100
            default_value = Decimal(default) / multiplier if default is not None else Decimal(1)
            shown = format(default_value, "f")
            while True:
                answer = self.read(f"Rate in {('pps', 'kpps', 'Mpps')[unit - 1]} [{shown}]: ").strip()
                if not answer:
                    answer = shown
                if len(answer) <= 80 and DECIMAL.fullmatch(answer):
                    try:
                        value = Decimal(answer) * multiplier
                    except InvalidOperation:
                        value = Decimal(0)
                    if value == value.to_integral_value() and 1 <= value <= MAX_PPS:
                        return int(value)
                self.write("Enter a positive rate equivalent to 1..1,000,000,000 whole packets per second.")

    def count(self, default=10_000_000, minimum=0):
        _integer(minimum, 0, UINT64_MAX, "Minimum packet count")
        _integer(default, 1, UINT64_MAX, "Default packet count")
        mode = self.choice("Packet count", ["A fixed total number of packets", "Continue until stopped"],
                           2 if default == UINT64_MAX else 1)
        if mode == 2:
            return UINT64_MAX
        return self.integer("Total packet count", max(1, minimum), UINT64_MAX, max(default, minimum))

    def ttl(self, default=(64, 64)):
        low, high = default
        _integer(low, 1, 255, "Default minimum TTL")
        _integer(high, low, 255, "Default maximum TTL")
        mode = self.choice("IPv4 TTL", ["Fixed TTL", "Random TTL within an inclusive range"], 1 if low == high else 2)
        if mode == 1:
            value = self.integer("TTL", 1, 255, low)
            return value, value
        low = self.integer("Minimum TTL (included)", 1, 255, low)
        high = self.integer("Maximum TTL (included)", low, 255, max(low, high))
        return low, high

    def _name(self, default, existing_names):
        while True:
            answer = self.read(f"Stream name [{default}]: ").strip() or default
            if not NAME.fullmatch(answer):
                self.write("Use 1..31 ASCII letters, digits, _ or - for the stream name.")
            elif answer in existing_names:
                self.write("That stream name is already in use. Choose a unique name.")
            else:
                return answer

    def _tcp_profile(self, default="syn", acknowledgment=0, *, allow_session=False):
        while self.choice("TCP packet mode", ["Raw packets (no connection or handshake)",
                          "Complete DPDK TCP connections (three-way handshake and data)"]) == 2:
            if allow_session:
                raise SessionRequested
            self.write("Stop the current raw-stream run and choose complete TCP connections from setup. "
                       "The same DPDK NIC cannot run both modes together.")
        self.write("Raw flags describe a header; they do not establish a valid TCP connection.")
        flags = TCP_PROFILES[self.choice("Raw TCP flag profile", list(TCP_PROFILE_LABELS),
                                         TCP_PROFILES.index(default) + 1) - 1]
        ack = self.integer("TCP acknowledgment number", 0, UINT32_MAX, acknowledgment) if "ack" in flags else 0
        return flags, ack

    def stream(self, existing_names, *, allow_session=False):
        if len(existing_names) >= MAX_STREAMS:
            raise ValueError("At most 16 simultaneous streams are supported")
        protocol = PROTOCOLS[self.choice("Packet protocol", list(PROTOCOL_LABELS)) - 1]
        flags, acknowledgment = self._tcp_profile(allow_session=allow_session) if protocol == "tcp" else ("syn", 0)
        index = 1
        while f"{protocol}{index}" in existing_names:
            index += 1
        name = self._name(f"{protocol}{index}", existing_names)
        pps = self.rate()
        count = self.count()
        low, high = self.ttl()
        result = Stream(name, protocol, pps, count, low, high, 6 if protocol == "tcp" else 18, self._next_seed)
        result.tcp_flags, result.tcp_ack = flags, acknowledgment
        self._next_seed += 1
        return result

    def _stream_advanced(self, stream):
        while True:
            action = self.choice("Advanced stream settings", [f"Payload bytes: {stream.payload}",
                                 f"Random seed: {stream.seed}",
                                 f"Initial state: {'paused' if stream.paused else 'running'}", "Back"], 4)
            if action == 1:
                stream.payload = self.integer("Payload bytes", 0, 1400, stream.payload)
            elif action == 2:
                stream.seed = self.integer("Random seed", 1, UINT64_MAX, stream.seed)
            elif action == 3:
                stream.paused = self.choice("Initial state", ["Running", "Paused"], 2 if stream.paused else 1) == 2
            else:
                return

    def edit_stream(self, stream, existing_names, *, allow_session=False):
        """Edit a configured stream in place; existing_names may include its name."""
        other_names = set(existing_names) - {stream.name}
        while True:
            action = self.choice(f"Edit stream {stream.name}", ["Name", "Protocol", "Sending rate", "Packet count",
                                 "TTL", "Advanced stream settings", "Back"], 7)
            if action == 1:
                stream.name = self._name(stream.name, other_names)
            elif action == 2:
                old_default = 6 if stream.protocol == "tcp" else 18
                protocol = PROTOCOLS[self.choice("Packet protocol", list(PROTOCOL_LABELS),
                                                 PROTOCOLS.index(stream.protocol) + 1) - 1]
                flags, acknowledgment = self._tcp_profile(stream.tcp_flags, stream.tcp_ack,
                                                          allow_session=allow_session) if protocol == "tcp" else ("syn", 0)
                stream.protocol, stream.tcp_flags, stream.tcp_ack = protocol, flags, acknowledgment
                if stream.payload == old_default:
                    stream.payload = 6 if stream.protocol == "tcp" else 18
            elif action == 3:
                stream.pps = self.rate(stream.pps)
            elif action == 4:
                stream.count = self.count(stream.count)
            elif action == 5:
                stream.ttl_min, stream.ttl_max = self.ttl((stream.ttl_min, stream.ttl_max))
            elif action == 6:
                self._stream_advanced(stream)
            else:
                return stream

    def _validated(self, label, default, validator):
        while True:
            answer = self.read(f"{label} [{default}]: ").strip() or default
            try:
                return validator(answer)
            except ValueError as error:
                self.write(str(error) + ".")

    def edit_network(self, config):
        config.src_ip = self._validated("Source IPv4", config.src_ip, lab_ip)
        config.dst_ip = self._validated("Destination IPv4", config.dst_ip, lab_ip)
        config.dst_mac = self._validated("Receiver destination MAC", config.dst_mac, unicast_mac)

    def _advanced(self, config, cpus):
        while True:
            action = self.choice("Advanced generator settings", [f"TX CPU ID (one worker): {config.core}",
                                 f"DPDK memory: {config.memory_mib} MiB", f"Burst size: {config.burst}",
                                 f"TX descriptors: {config.tx_descriptors}", f"Packet template: {config.template}",
                                 f"Duration: {str(config.duration_ms) + ' ms' if config.duration_ms else 'until stopped'}",
                                 f"UDP/TCP ports: {config.src_port} -> {config.dst_port}", "Back"], 8)
            if action == 1:
                self.write("This selects one CPU ID, not a core count. DPDK polling dedicates that CPU to one TX worker.")
                config.core = cpus[self.choice("Allowed TX CPU ID (one worker)", [str(cpu) for cpu in cpus],
                                              cpus.index(config.core) + 1) - 1]
            elif action == 2:
                self.write("This uses existing prepared memory; the wizard does not reserve hugepages.")
                config.memory_mib = self.integer("DPDK memory (MiB)", 64, 65536, config.memory_mib)
            elif action == 3:
                config.burst = self.integer("Packets per burst", 1, 256, config.burst)
            elif action == 4:
                descriptors = [64, 128, 256, 512, 1024, 2048, 4096]
                config.tx_descriptors = descriptors[self.choice("TX descriptors", [str(n) for n in descriptors],
                                                               descriptors.index(config.tx_descriptors) + 1) - 1]
            elif action == 5:
                config.template = ("static", "sequence")[self.choice("Packet template", ["Static (fastest)",
                                  "Sequence (updates packet identifiers)"], 1 if config.template == "static" else 2) - 1]
            elif action == 6:
                timed = self.choice("Duration", ["Continue until stopped", "Set a time limit"],
                                    2 if config.duration_ms else 1)
                config.duration_ms = self.integer("Time limit (milliseconds)", 1, 3_600_000,
                                                 config.duration_ms or 10_000) if timed == 2 else 0
            elif action == 7:
                config.src_port = self.integer("UDP/TCP source port", 1, 65535, config.src_port)
                config.dst_port = self.integer("UDP/TCP destination port", 1, 65535, config.dst_port)
            else:
                return

    def _review(self, config):
        self.write("\nReview generator settings")
        self.write(f"  Prepared NIC {config.pci}; TX CPU ID {config.core} (one worker); {config.memory_mib} MiB; "
                   f"burst {config.burst}; descriptors {config.tx_descriptors}; template {config.template}")
        self.write(f"  IPv4 {config.src_ip} -> {config.dst_ip}; destination MAC {config.dst_mac}")
        self.write(f"  UDP/TCP ports {config.src_port} -> {config.dst_port}; "
                   f"duration {str(config.duration_ms) + ' ms' if config.duration_ms else 'until stopped'}")
        for stream in config.streams:
            rate = "maximum speed" if stream.pps is None else f"{stream.pps:,} pps"
            count = "until stopped" if stream.count == UINT64_MAX else f"{stream.count:,} packets"
            ttl = str(stream.ttl_min) if stream.ttl_min == stream.ttl_max else f"random {stream.ttl_min}..{stream.ttl_max} inclusive"
            protocol = PROTOCOL_LABELS[PROTOCOLS.index(stream.protocol)]
            if stream.protocol == "tcp":
                protocol += f" raw {stream.tcp_flags.upper()}"
                if "ack" in stream.tcp_flags:
                    protocol += f" (acknowledgment {stream.tcp_ack})"
            self.write(f"  {stream.name}: {protocol}; {rate}; {count}; TTL {ttl}; payload {stream.payload}; "
                       f"seed {stream.seed}; {'paused' if stream.paused else 'running'}")

    def _mode_advanced(self, config, cpus):
        while True:
            session = config.session if config.mode == "sessions" else None
            count = len(session.worker_cores) if session is not None else 1
            settings = [f"First worker CPU ID: {config.core}" if session is not None else
                        f"CPU ID (one worker): {config.core}",
                        f"DPDK memory: {config.memory_mib} MiB"]
            if session is not None:
                settings.append(f"TCP workers: {count}")
            settings.append("Back")
            action = self.choice("DPDK settings", settings, len(settings))
            if action == 1:
                self.write("DPDK polling dedicates one selected CPU to each worker.")
                choices = [cpu for cpu in cpus if cpu < 128] if session is not None else cpus
                index = self.choice("First allowed DPDK CPU ID", [str(cpu) for cpu in choices],
                                    choices.index(config.core) + 1) - 1
                if index + count > len(choices):
                    self.write("There are not enough allowed CPUs after this CPU for the selected worker count.")
                    continue
                config.core = choices[index]
                if session is not None:
                    session.core = config.core
                    session.cores = tuple(choices[index:index + count]) if count > 1 else None
            elif action == 2:
                self.write("This uses existing prepared memory; the wizard does not reserve hugepages.")
                config.memory_mib = self.integer("DPDK memory (MiB)", 64, 65536, config.memory_mib)
            elif session is not None and action == 3:
                choices = [cpu for cpu in cpus if cpu < 128]
                first = choices.index(config.core)
                available = min(len(choices) - first, session.connections, session.concurrency)
                if session.cps is not None:
                    available = min(available, session.cps)
                counts = [value for value in (1, 2, 4, 8) if value <= available]
                self.write("Workers use consecutive allowed CPU IDs starting with the first selected CPU.")
                self.write("Quota, concurrency and client rate are global totals divided between workers; memory is shared.")
                selected = counts[self.choice("TCP worker count", [str(value) for value in counts],
                                              counts.index(count) + 1 if count in counts else 1) - 1]
                session.cores = tuple(choices[first:first + selected]) if selected > 1 else None
            else:
                return

    def connection_rate(self, default=100):
        if default is not None:
            _integer(default, 1, MAX_SESSION_CPS, "Default client connection attempt rate")
        shown = "max" if default is None else str(default)
        self.write("Client attempt rate: enter 1..1,000,000,000 connections/s or max for maximum available speed.")
        self.write("Maximum removes the application rate pacer; completed connections/s is measured separately.")
        while True:
            answer = self.read(f"New client connections per second [{shown}]: ").strip().lower()
            if not answer:
                return default
            if answer in ("max", "maximum"):
                return None
            if len(answer) <= 20 and INTEGER.fullmatch(answer):
                value = int(answer)
                if 1 <= value <= MAX_SESSION_CPS:
                    return value
            self.write("Enter a positive whole client attempt rate up to 1,000,000,000, or max.")

    def _session_values(self, session):
        expected_role = LAB_SESSION_ROLES.get(self.hostname)
        while True:
            role = ("client", "server")[self.choice("TCP connection role",
                    ["Client on VM 104", "Server on VM 105"], 1 if session.role == "client" else 2) - 1]
            if expected_role is None or role == expected_role:
                break
            expected_vm = "VM 104" if expected_role == "client" else "VM 105"
            self.write(f"This machine is {self.hostname} ({expected_vm}). Choose {expected_role.title()} here. "
                       "The client and server must run on their corresponding VMs.")
        if role != session.role and session.duration_seconds == (300 if session.role == "server" else 30):
            session.duration_seconds = 300 if role == "server" else 30
        session.role = role
        self.write(f"Fixed lab flow: {session.local_ip} -> {session.peer_ip}. Start the server before the client.")
        workers = len(session.worker_cores)
        session.port = self.integer("TCP service port", 1024, 65535, session.port)
        session.connections = self.integer("Connection attempt quota (server: accept quota)", workers, UINT32_MAX, session.connections)
        session.concurrency = self.integer("Maximum concurrent connections", workers, min(MAX_SESSION_CONCURRENCY, session.connections),
                                           min(session.concurrency, session.connections))
        if session.role == "client":
            while True:
                rate = self.connection_rate(session.cps)
                if rate is None or rate >= workers:
                    session.cps = rate
                    break
                self.write(f"A positive global client rate must be at least {workers} for {workers} workers; max removes pacing.")
        else:
            self.write("Server accepts incoming connections; the client's CPS setting does not pace the server.")
        session.duration_seconds = self.integer("Maximum duration (seconds)", 1, 3600, session.duration_seconds)
        session.timeout_seconds = self.integer("Connection timeout (seconds)", 1, 30, session.timeout_seconds)
        session.payload = self.integer("Data bytes per connection", 1, 1400, session.payload)
        session.ttl_min, session.ttl_max = self.ttl((session.ttl_min, session.ttl_max))

    def _connections(self, config, cpus):
        config.mode, config.streams, config.replay = "sessions", [], None
        session = config.session or SessionConfig(role=LAB_SESSION_ROLES.get(self.hostname, "client"),
                                                  pci=config.pci, core=config.core, memory_mib=config.memory_mib)
        config.session = session
        self.write("Complete TCP uses the DPDK-native connection engine. It runs separately from raw streams and replay.")
        self._session_values(session)
        while True:
            session.pci, session.core, session.memory_mib = config.pci, config.core, config.memory_mib
            self.write("\nReview complete DPDK TCP connections")
            workers = len(session.worker_cores)
            placement = (f"CPU ID {session.core} (one worker)" if workers == 1 else
                         f"CPU IDs {','.join(str(cpu) for cpu in session.worker_cores)} ({workers} workers)")
            memory = f"{session.memory_mib} MiB" + (" shared hugepages" if workers > 1 else "")
            self.write(f"  {session.role}; {session.local_ip} -> {session.peer_ip}; TCP port {session.port}; "
                       f"NIC {session.pci}; {placement}; {memory}")
            rate = ("maximum client attempt rate (unpaced)" if session.cps is None else
                    f"{session.cps:,} client connection attempts/s") if session.role == "client" else (
                    "server accepts incoming connections without a CPS pacer")
            self.write(f"  {session.connections:,} {'attempt' if session.role == 'client' else 'accept'} quota; "
                       f"up to {session.concurrency} concurrent; {rate}; data {session.payload} bytes/connection")
            if workers > 1:
                self.write("  Quota, concurrency and client rate are global totals divided between workers.")
            ttl = (f"TTL fixed {session.ttl_min}" if session.ttl_min == session.ttl_max else
                   f"TTL random inclusive {session.ttl_min}..{session.ttl_max}")
            self.write(f"  Duration limit {session.duration_seconds}s; connection timeout {session.timeout_seconds}s; "
                       f"{ttl} per outgoing TCP packet; three-way handshake and data exchange")
            action = self.choice("What next?", ["Start TCP connection engine", "Edit connection settings",
                                  "DPDK CPU and memory settings", "Cancel"])
            if action == 1:
                session.validate()
                config.src_ip, config.dst_ip, config.dst_mac = session.local_ip, session.peer_ip, session.peer_mac
                return config
            if action == 2:
                self._session_values(session)
            elif action == 3:
                self._mode_advanced(config, cpus)
            else:
                self.write("Setup cancelled. No traffic was started.")
                return None

    def _replay_values(self, replay):
        replay.path = self._validated("PCAP file path", replay.path, replay_path)
        replay.loops = self.integer("Number of capture passes (0 continues until Ctrl+C)", 0, 10000, replay.loops)
        replay.original_timing = self.choice("Replay timing", ["Set a packet sending rate",
                                            "Use original capture timing"], 2 if replay.original_timing else 1) == 2
        replay.pps = None if replay.original_timing else self.rate(replay.pps if replay.pps is not None else 1000)
        limited = self.choice("Replay packet count", ["All packets in the selected capture passes",
                              "Stop after a fixed packet total"], 2 if replay.count is not None else 1) == 2
        replay.count = self.integer("Maximum replayed packets", 1, UINT64_MAX, replay.count or 1000) if limited else None
        override = self.choice("Replay IPv4 TTL", ["Preserve captured TTL values", "Set a fixed TTL"],
                               2 if replay.ttl is not None else 1) == 2
        replay.ttl = self.integer("Replay IPv4 TTL", 1, 255, replay.ttl or 64) if override else None

    def _replay(self, config, cpus):
        config.mode, config.streams, config.session = "replay", [], None
        replay = config.replay or ReplayConfig(path="")
        config.replay = replay
        self.write("PCAP replay sends recorded packets. Recorded TCP sequence and ACK values do not establish live TCP connections.")
        self.write("The launcher validates the capture before sending; use captures for the isolated VM 104/105 lab flow.")
        self._replay_values(replay)
        while True:
            self.write("\nReview PCAP replay")
            passes = f"{replay.loops} pass(es)" if replay.loops else "repeat until stopped"
            self.write(f"  File: {replay.path}; {passes}; NIC {config.pci}; "
                       f"CPU ID {config.core} (one worker); {config.memory_mib} MiB")
            timing = "original capture timing" if replay.original_timing else (
                "maximum available speed" if replay.pps is None else f"{replay.pps:,} pps")
            self.write(f"  Timing: {timing}; packet limit: {replay.count if replay.count is not None else 'all capture packets'}; "
                       f"IPv4 TTL: {replay.ttl if replay.ttl is not None else 'preserve capture'}")
            action = self.choice("What next?", ["Validate capture and start replay", "Edit replay settings",
                                  "DPDK CPU and memory settings", "Cancel"])
            if action == 1:
                replay.validate()
                return config
            if action == 2:
                self._replay_values(replay)
            elif action == 3:
                self._mode_advanced(config, cpus)
            else:
                self.write("Setup cancelled. No traffic was started.")
                return None

    def configure(self, devices, cpus):
        """Ask for a configuration using only the launcher's prepared resources."""
        devices = list(dict.fromkeys(devices))
        cpus = sorted(set(cpus))
        if not devices:
            self.write("No prepared DPDK NIC is available. Prepare the intended data NIC before starting.")
            return None
        if any(not isinstance(device, str) or not PCI.fullmatch(device) for device in devices):
            raise ValueError("Prepared NICs must use full PCI addresses such as 0000:00:13.0")
        if not cpus:
            self.write("No allowed CPU core is available.")
            return None
        if any(type(cpu) is not int or not 0 <= cpu <= 65535 for cpu in cpus):
            raise ValueError("Allowed CPU cores must be integers from 0 to 65535")
        self.write("CornuCat setup. Press Enter to keep a displayed default; Ctrl+C cancels.")
        mode = self.choice("Generator mode", ["Simultaneous raw packet streams (UDP / TCP / ICMP)",
                           "Complete DPDK-native TCP connections", "PCAP replay"])
        pci = devices[self.choice("Prepared DPDK data NIC", devices) - 1]
        config = Config(pci=pci, core=cpus[0])
        self.write("CPU ID selects one worker's CPU, not the number of cores. DPDK polling dedicates that CPU while running.")
        if mode == 2:
            return self._connections(config, cpus)
        if mode == 3:
            return self._replay(config, cpus)
        self.write(f"Network defaults: {config.src_ip} -> {config.dst_ip}, destination MAC {config.dst_mac}")
        if self.choice("Lab network addresses", ["Use these addresses", "Edit addresses"]) == 2:
            self.edit_network(config)
        try:
            config.streams.append(self.stream(set(), allow_session=True))
        except SessionRequested:
            return self._connections(config, cpus)
        while True:
            self._review(config)
            action = self.choice("What next?", ["Start traffic", "Add another stream", "Edit a stream",
                                 "Edit network addresses", "Advanced generator settings", "Cancel"])
            if action == 1:
                for stream in config.streams:
                    stream.spec()
                return config
            if action == 2:
                if len(config.streams) == MAX_STREAMS:
                    self.write("The limit is 16 simultaneous streams. Edit an existing stream instead.")
                else:
                    try:
                        config.streams.append(self.stream({stream.name for stream in config.streams}, allow_session=True))
                    except SessionRequested:
                        return self._connections(config, cpus)
            elif action == 3:
                index = self.choice("Choose a stream to edit", [stream.name for stream in config.streams]) - 1
                try:
                    self.edit_stream(config.streams[index], {stream.name for stream in config.streams}, allow_session=True)
                except SessionRequested:
                    return self._connections(config, cpus)
            elif action == 4:
                self.edit_network(config)
            elif action == 5:
                self._advanced(config, cpus)
            elif action == 6:
                self.write("Setup cancelled. No traffic was started.")
                return None
