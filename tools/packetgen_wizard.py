#!/usr/bin/env python3
"""No-argument terminal front end for CornuCat."""
from __future__ import annotations

import ctypes
try:
    import fcntl
except ImportError:  # Allow help and pure-input tests on non-Linux hosts.
    fcntl = None
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

from packetgen_control import render_watch, request
from wizard_inputs import Config, Prompt

PCI = re.compile(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]")


def discover_devices(sysfs=Path('/sys/bus/pci/devices')):
    """List prepared network devices only. Never detach or rebind a driver."""
    devices = []
    try:
        entries = sorted(sysfs.iterdir())
    except OSError:
        return devices
    for device in entries:
        try:
            if (PCI.fullmatch(device.name) and
                    int((device / 'class').read_text().strip(), 16) >> 8 == 0x0200 and
                    (device / 'driver').resolve(strict=True).name == 'vfio-pci'):
                devices.append(device.name)
        except (OSError, ValueError):
            continue
    return devices


def choose_backend(root):
    binary = root / 'build/packetgen-dpdk'
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError('Native engine is missing. Build CornuCat with make dpdk first.')
    return binary.resolve()


def backend_command(binary, config, socket_path, stats_path):
    """Return separate argv elements; no shell receives any user input."""
    command = [str(binary), '-l', str(config.core), '--main-lcore', str(config.core),
               '-a', config.pci + ',vectorized=1', '--force-max-simd-bitwidth', '512',
               '--file-prefix', 'pg_wizard_' + socket_path.parent.name,
               '--huge-unlink=always', '--iova-mode=pa', '-m', str(config.memory_mib), '--',
               '--mode', 'dpdk', '--port-id', '0', '--src-ip', config.src_ip,
               '--dst-ip', config.dst_ip, '--dst-mac', config.dst_mac,
               '--src-port', str(config.src_port), '--dst-port', str(config.dst_port),
               '--workers', '1', '--flows', '1', '--pacing', 'smooth',
               '--burst', str(config.burst), '--tx-descriptors', str(config.tx_descriptors),
               '--template', config.template, '--control-socket', str(socket_path),
               '--stats-json', str(stats_path)]
    if config.duration_ms:
        command += ['--duration-ms', str(config.duration_ms)]
    for stream in config.streams:
        command += ['--stream', stream.spec()]
    return command


def replay_command(binary, config, session, stats_path, capture_path):
    replay = config.replay.validate()
    # Reuse the selected native device settings, but do not create a raw-stream
    # control socket: recorded frames have their own ordering and timing.
    command = [str(binary), '-l', str(config.core), '--main-lcore', str(config.core),
               '-a', config.pci + ',vectorized=1', '--force-max-simd-bitwidth', '512',
               '--file-prefix', 'pg_replay_' + session.name,
               '--huge-unlink=always', '--iova-mode=pa', '-m', str(config.memory_mib), '--',
               '--mode', 'dpdk', '--port-id', '0', '--src-ip', config.src_ip,
               '--dst-ip', config.dst_ip, '--dst-mac', config.dst_mac,
               '--burst', str(config.burst), '--tx-descriptors', str(config.tx_descriptors),
               '--stats-json', str(stats_path), '--replay', str(capture_path),
               '--replay-loops', str(replay.loops), '--replay-timing',
               'original' if replay.original_timing else 'rate']
    if not replay.original_timing:
        command += ['--unlimited'] if replay.pps is None else ['--pps', str(replay.pps)]
    if replay.count is not None:
        command += ['--count', str(replay.count)]
    if replay.ttl is not None:
        command += ['--ttl', str(replay.ttl)]
    if config.duration_ms:
        command += ['--duration-ms', str(config.duration_ms)]
    return command


def inspect_replay(root, config, session):
    """Freeze the selected capture in this owned session before validating it."""
    replay = config.replay.validate()
    capture = Path(replay.path).expanduser().resolve(strict=True)
    # Copy a bounded snapshot so a later replacement of the user's pathname
    # cannot change the bytes transmitted after the preview.
    target = session / 'input.pcap'
    descriptor = os.open(capture, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024:
            raise ValueError('Replay requires a regular classic PCAP file of at most 64 MiB.')
    except BaseException:
        os.close(descriptor)
        raise
    with os.fdopen(descriptor, 'rb') as source:
        data = source.read(64 * 1024 * 1024 + 1)
        if len(data) > 64 * 1024 * 1024:
            raise ValueError('Replay capture exceeds 64 MiB.')
        with target.open('xb') as output:
            output.write(data)
    inspector = root / 'build/inspect-pcap'
    if not inspector.is_file() or not os.access(inspector, os.X_OK):
        raise RuntimeError('PCAP inspector is missing. Rebuild with make dpdk.')
    result = subprocess.run([str(inspector), str(target), config.src_ip, config.dst_ip],
                            capture_output=True, text=True, timeout=10, check=False)
    if result.returncode:
        raise ValueError('PCAP validation failed: ' + result.stderr.strip()[:500])
    summary = json.loads(result.stdout)
    if not isinstance(summary, dict) or not all(type(summary.get(key)) is int and summary[key] >= 0
            for key in ('packets', 'captured_bytes', 'frame_bytes', 'duration_ns', 'udp', 'tcp', 'icmp')):
        raise RuntimeError('Invalid PCAP inspector response.')
    summary['sha256'] = hashlib.sha256(data).hexdigest()
    (session / 'capture.json').write_text(json.dumps(summary, indent=2) + '\n')
    return target, summary


def stop_simple(child):
    if child.poll() is not None:
        return
    child.send_signal(signal.SIGINT)
    try:
        child.wait(timeout=6)
        return
    except subprocess.TimeoutExpired:
        child.terminate()
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=2)


def session_display(prompt, document, previous):
    """Rates are deltas of stack-published counters over its own sample time."""
    if document.get('mode') != 'tcp-sessions' or document.get('backend') != 'f-stack':
        raise ValueError('Invalid native TCP session status.')
    for key in ('attempted', 'connected', 'completed', 'failed', 'active', 'verified_bytes'):
        if type(document.get(key)) is not int or document[key] < 0:
            raise ValueError('Invalid native TCP session counters.')
    elapsed = document.get('elapsed_seconds')
    if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
        raise ValueError('Invalid TCP session sample time.')
    if previous is not None and (elapsed < previous['elapsed_seconds'] or
                                document['completed'] < previous['completed']):
        raise ValueError('Native TCP session counters regressed.')
    cps = 0.0
    if previous is not None and elapsed > previous['elapsed_seconds']:
        cps = (document['completed'] - previous['completed']) / (elapsed - previous['elapsed_seconds'])
    prompt.write(f"TCP {document.get('role')} | {document.get('state')} | "
                 f"{cps:,.1f} completed connections/s | active {document['active']} | "
                 f"connected {document['connected']:,} | completed {document['completed']:,} | "
                 f"failed {document['failed']:,} | verified {document['verified_bytes']:,} bytes")
    return document


def owned_simple_run(command, session, prompt, mode, *, popen=subprocess.Popen):
    """Own one replay or TCP-stack process and stop only that exact child."""
    child = None
    cancelled = False
    previous = None
    stale = False
    try:
        with (session / 'engine.stdout.log').open('x') as out, (session / 'engine.stderr.log').open('x') as err:
            parent = os.getpid()
            child = popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                          cwd=session, shell=False, close_fds=True,
                          preexec_fn=lambda: child_setup(parent))
            prompt.write('Starting native ' + mode + '. Ctrl+C stops this process.')
            with (session / 'engine.stdout.log').open() as log:
                while child.poll() is None:
                    if mode == 'TCP sessions':
                        live = session / 'live.json'
                        if live.is_file() and live.stat().st_size:
                            document = json.loads(live.read_text())
                            if previous is None or document.get('elapsed_seconds') != previous.get('elapsed_seconds'):
                                previous = session_display(prompt, document, previous)
                            expired = time.time() - live.stat().st_mtime > 3
                            if expired and not stale:
                                prompt.write('Status is stale; no current rate is claimed.')
                            stale = expired
                    else:
                        for line in log.readlines():
                            if line.startswith('TX submitted:'):
                                prompt.write(line.rstrip())
                    # EOF from a closed terminal must stop the owned engine too.
                    readable, _, _ = select.select([sys.stdin], [], [], 0.2)
                    if readable and sys.stdin.readline() == '':
                        raise EOFError
    except (KeyboardInterrupt, EOFError):
        cancelled = True
        prompt.write('\nStopping and draining this native session...')
    finally:
        if child is not None:
            handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                stop_simple(child)
            finally:
                signal.signal(signal.SIGINT, handler)
        prompt.write('Reports: ' + str(session))
    stats = session / 'source.json'
    if stats.is_file() and stats.stat().st_size:
        result = json.loads(stats.read_text())
        if mode == 'TCP sessions':
            session_display(prompt, result, previous)
            prompt.write('Completed = verified echo and orderly receive EOF; connections/s differs from packets/s.')
        else:
            prompt.write(f"Replay finished: {result.get('submitted', 0):,} packets submitted; receiver delivery is measured separately.")
    if child is not None and child.returncode != 0 and not cancelled:
        raise RuntimeError('The native session reported a failure. See source.json and engine.stderr.log.')
    return 0


def create_session(base=Path('/var/tmp/packet-gen-dpdk')):
    try:
        base.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = base.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise RuntimeError('The report directory must be private and owned by the current user.')
    session = Path(tempfile.mkdtemp(prefix=time.strftime('%Y%m%d-%H%M%S-'), dir=base))
    if len(str(session / 'control.sock')) > 100:
        raise RuntimeError('The report directory produces an excessively long control-socket path.')
    return session


def available_hugepage_mib(meminfo=Path('/proc/meminfo')):
    values = {}
    for line in meminfo.read_text().splitlines():
        if ':' in line:
            key, rest = line.split(':', 1)
            try:
                values[key] = int(rest.split()[0])
            except (ValueError, IndexError):
                continue
    return max(0, values.get('HugePages_Free', 0) - values.get('HugePages_Rsvd', 0)) * values.get('Hugepagesize', 0) // 1024


def other_device_users(pci, proc=Path('/proc')):
    active = []
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            arguments = (entry / 'cmdline').read_bytes().split(b'\0')
            # F-Stack receives its allow-list through an INI path, so its PCI
            # identifier is absent from argv. Conservatively treat another
            # instance of this integration as a busy data port.
            native_tcp = arguments and Path(os.fsdecode(arguments[0])).name == 'tcp-session-fstack'
            if native_tcp or any(arg.decode('utf-8', 'replace').split(',', 1)[0].removeprefix('--allow=') == pci
                   for arg in arguments):
                active.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return active


def lock_device(pci, directory=Path('/run/lock')):
    if fcntl is None:
        raise RuntimeError('Device locking requires Linux.')
    if not PCI.fullmatch(pci):
        raise ValueError('Invalid prepared PCI device.')
    path = directory / ('packet-gen-dpdk-' + pci.replace(':', '_') + '.lock')
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RuntimeError('The device lock is not a private file owned by the current user.')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def status_streams(document):
    if not isinstance(document, dict):
        raise RuntimeError('Invalid stream status.')
    rows = document.get('streams')
    if document.get('ok') is not True or not isinstance(rows, list):
        raise RuntimeError(document.get('message', 'Invalid stream status.'))
    if not all(isinstance(row, dict) and isinstance(row.get('name'), str) and
               re.fullmatch(r'[A-Za-z0-9_-]{1,31}', row['name']) and
               row.get('protocol') in ('udp', 'tcp', 'icmp') and
               type(row.get('submitted')) is int and row['submitted'] >= 0 and
               type(row.get('quota')) is int and row['submitted'] <= row['quota'] < (1 << 64) and
               type(row.get('pps')) is int and 0 <= row['pps'] <= 1_000_000_000 and
               type(row.get('ttl_min')) is int and type(row.get('ttl_max')) is int and
               1 <= row['ttl_min'] <= row['ttl_max'] <= 255 and
               type(row.get('paused')) is bool and type(row.get('unlimited')) is bool and
               row.get('state') in ('running', 'backpressure', 'paused', 'complete') for row in rows):
        raise RuntimeError('Invalid stream counters.')
    return rows


def stream_selection(prompt, document):
    rows = status_streams(document)
    if not rows:
        prompt.write('There are no streams. Choose Add stream to create one.')
        return None
    selected = prompt.choice('Select stream', [f"{row['name']} ({row.get('protocol', '?')}, {row.get('state', '?')}, {row['submitted']:,} accepted)"
                                             for row in rows] + ['Back'])
    return rows[selected - 1] if selected <= len(rows) else None


def show_status(prompt, document):
    rows = status_streams(document)
    prompt.write('\nSender accepted/submitted counters (not receiver measurements)')
    for row in rows:
        rate = 'Maximum' if row.get('unlimited') else f"{row.get('pps', 0):,} pps"
        prompt.write(f"  {row['name']}: {row.get('protocol')} | {rate} | "
                     f"{row['submitted']:,} / {row.get('quota', 0):,} packets | "
                     f"TTL {row.get('ttl_min')}..{row.get('ttl_max')} | {row.get('state')}")


def dashboard(prompt, socket_path, child, request_fn=request):
    previous, last = {}, None
    prompt.write('Live sender dashboard. Press Enter for controls; Ctrl+C stops this sender.')
    while child.poll() is None:
        try:
            document = request_fn(socket_path, 'status')
        except OSError:
            if child.poll() is not None:
                return
            raise
        status_streams(document)
        sampled = time.monotonic()
        if sys.stdout.isatty():
            print('\033[2J\033[H', end='')
        # The standalone viewer's footer describes an independent client. The
        # wizard has an owned child, so it supplies its own lifecycle message.
        from io import StringIO
        from contextlib import redirect_stdout
        with StringIO() as buffer, redirect_stdout(buffer):
            current = render_watch(document, previous, sampled - last if last else 0, socket_path)
            rendered = buffer.getvalue()
        prompt.write(rendered.split('\nCtrl+C stops this display only;', 1)[0].rstrip())
        if any(row.get('state') == 'backpressure' for row in document['streams']):
            prompt.write('TX queue is blocked. Start/check the peer DPDK receiver; controls are still available.')
        prompt.write('\nEnter: controls | Ctrl+C: stop this sender')
        previous, last = current, sampled
        readable, _, _ = select.select([sys.stdin], [], [], 1)
        if readable:
            if sys.stdin.readline() == '':
                raise EOFError
            return


def runtime_menu(prompt, socket_path, child, request_fn=request, dashboard_fn=dashboard):
    while child.poll() is None:
        selected = prompt.choice('Live controls', ['Live dashboard', 'Show stream totals',
            'Pause or resume a stream', 'Change sending rate', 'Change packet count',
            'Change TTL', 'Add stream', 'Remove stream', 'Stop traffic'], default=1)
        if child.poll() is not None:
            return
        if selected == 1:
            dashboard_fn(prompt, socket_path, child, request_fn)
            continue
        document = request_fn(socket_path, 'status')
        rows = status_streams(document)
        if selected == 2:
            show_status(prompt, document)
            continue
        if selected == 9:
            reply = request_fn(socket_path, 'stop')
            if reply.get('ok') is not True:
                raise RuntimeError(reply.get('message', 'Stop was rejected.'))
            return
        if selected == 7:
            if len(rows) >= 16:
                prompt.write('All 16 stream slots are occupied. Remove one before adding another.')
                continue
            stream = prompt.stream({row['name'] for row in rows})
            command = 'add ' + stream.spec()
        else:
            row = stream_selection(prompt, document)
            if row is None:
                continue
            name = row['name']
            if selected == 3:
                command = ('resume ' if row.get('paused') else 'pause ') + name
            elif selected == 4:
                rate = prompt.rate(None if row.get('unlimited') else row['pps'])
                command = 'rate ' + name + ' ' + ('unlimited' if rate is None else str(rate))
            elif selected == 5:
                prompt.write(f"Already accepted: {row['submitted']:,}. Enter a lifetime total, not an additional count.")
                count = prompt.count(default=row['quota'], minimum=row['submitted'])
                command = f'count {name} {count}'
            elif selected == 6:
                low, high = prompt.ttl((row['ttl_min'], row['ttl_max']))
                command = f'ttl {name} {low} {high}'
            else:
                if prompt.choice('Remove ' + name + '?', ['Cancel', 'Remove'], default=1) == 1:
                    continue
                command = 'remove ' + name
        reply = request_fn(socket_path, command)
        if reply.get('ok') is True:
            prompt.write('Change applied.')
        else:
            prompt.write('Change rejected: ' + str(reply.get('message', 'Unknown error.')))


def stop_owned(child, socket_path, request_fn=request):
    if child.poll() is not None:
        return
    try:
        request_fn(socket_path, 'stop', timeout=1)
    except (OSError, ValueError, RuntimeError):
        pass
    try:
        child.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        child.send_signal(signal.SIGINT)
    try:
        child.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        child.terminate()
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=2)


def child_setup(parent):
    """A closed/crashed wizard must not leave its packet engine running."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGINT, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(1)


def owned_run(command, socket_path, stats_path, prompt, *, request_fn=request,
              dashboard_fn=dashboard, menu_fn=runtime_menu, popen=subprocess.Popen):
    child = None
    cancelled = False
    session = socket_path.parent
    try:
        with (session / 'engine.stdout.log').open('x') as out, (session / 'engine.stderr.log').open('x') as err:
            parent = os.getpid()
            child = popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                          cwd=session, shell=False, close_fds=True,
                          preexec_fn=lambda: child_setup(parent))
            deadline = time.monotonic() + 12
            while True:
                if child.poll() is not None:
                    raise RuntimeError('The engine exited before it was ready. See engine.stderr.log in the report directory.')
                try:
                    status_streams(request_fn(socket_path, 'status', timeout=0.3))
                    break
                except (FileNotFoundError, ConnectionRefusedError, TimeoutError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError('The engine did not become ready within 12 seconds.')
                    time.sleep(0.05)
            prompt.write('\nTraffic started. The dashboard shows sender accepted rates.')
            dashboard_fn(prompt, socket_path, child, request_fn)
            if child.poll() is None:
                menu_fn(prompt, socket_path, child, request_fn=request_fn, dashboard_fn=dashboard_fn)
    except (KeyboardInterrupt, EOFError):
        cancelled = True
        prompt.write('\nStopping this sender and draining its accepted packets...')
    except OSError as error:
        # The server unlinks its socket during normal teardown, just before the
        # process exits. A timer expiring during a status request is normal.
        if child is None:
            raise
        try:
            child.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            raise error
        # A closed control socket is a symptom of engine exit. Report the
        # engine's final reason below rather than exposing only ECONNRESET.
    finally:
        if child is not None:
            old_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                stop_owned(child, socket_path, request_fn)
            finally:
                signal.signal(signal.SIGINT, old_handler)
        prompt.write('Reports: ' + str(session))
    if child is not None and child.returncode != 0 and not cancelled:
        if stats_path.is_file() and stats_path.stat().st_size:
            result = json.loads(stats_path.read_text())
            raise RuntimeError('The packet engine stopped: ' + str(result.get('stop_reason', 'unknown')) +
                               '. See source.json and engine.stderr.log.')
        raise RuntimeError('The packet engine reported an error. See engine.stderr.log and source.json.')
    if stats_path.is_file():
        result = json.loads(stats_path.read_text())
        prompt.write(f"Session finished: {result.get('submitted', 0):,} packets accepted; "
                     f"status {result.get('status', 'unknown')}.")
    return 0


def launch(config, prompt, root):
    if config.mode == 'sessions':
        from native_sessions import validate_lab_role
        validate_lab_role(config.session, socket.gethostname())
        # This is the fixed queue budget of these prepared lab profiles, not a
        # generic inference from the number of CPUs or PCI MSI-X vectors.
        if (socket.gethostname() in ('dpdk-review-ubuntu', 'dpdk-receiver-ubuntu') and
                config.pci == '0000:00:13.0' and len(config.session.worker_cores) > 4):
            raise RuntimeError('The preserved PCI13 link has four queues and supports at most four TCP workers. '
                               'Use the prepared tcp-eight-core helper for the temporary eight-queue lab path.')
    binary = choose_backend(root)
    if config.pci not in discover_devices():
        raise RuntimeError('The selected data NIC is no longer prepared for DPDK.')
    if config.core not in os.sched_getaffinity(0):
        raise RuntimeError('The selected CPU is unavailable.')
    if config.mode == 'sessions' and not set(config.session.worker_cores).issubset(os.sched_getaffinity(0)):
        raise RuntimeError('A selected TCP worker CPU is unavailable.')
    if available_hugepage_mib() < config.memory_mib:
        raise RuntimeError('There is insufficient free hugepage memory for this session. No settings were changed.')
    lock = lock_device(config.pci)
    try:
        if other_device_users(config.pci):
            raise RuntimeError('Another process is using this data NIC. Stop that test before starting this session.')
        session = create_session()
        if config.mode == 'sessions':
            from native_sessions import stack_configuration, session_command
            binary = root / 'build/tcp-session-fstack'
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise RuntimeError('The optional F-Stack TCP engine is missing. Build make tcp-session with FSTACK_DIR set.')
            if len(config.session.worker_cores) > 1:
                from native_multi import owned_multi_run
                return owned_multi_run(binary, config.session, session, prompt)
            ini = session / 'fstack.ini'
            ini.write_text(stack_configuration(config.session, session))
            command = session_command(binary, config.session, ini, session / 'source.json', session / 'live.json')
        elif config.mode == 'replay':
            capture, summary = inspect_replay(root, config, session)
            prompt.write(f"Validated PCAP: {summary['packets']:,} frames | UDP {summary['udp']:,} | "
                         f"TCP {summary['tcp']:,} | ICMP {summary['icmp']:,}. Replay transmits recorded frames.")
            command = replay_command(binary, config, session, session / 'source.json', capture)
        else:
            command = backend_command(binary, config, session / 'control.sock', session / 'source.json')
        record = {'schema_version': 1, 'engine_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                  'command': command, 'note': 'Arguments were assembled internally by the interactive wizard.'}
        (session / 'configuration.json').write_text(json.dumps(record, indent=2) + '\n')
        if config.mode != 'streams':
            return owned_simple_run(command, session, prompt,
                                    'TCP sessions' if config.mode == 'sessions' else 'PCAP replay')
        return owned_run(command, session / 'control.sock', session / 'source.json', prompt)
    finally:
        os.close(lock)


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if arguments in (['--help'], ['-h']):
        print('Run CornuCat with ./packet-gen-dpdk without parameters. Follow the numbered setup and live-control menus.')
        return 0
    if arguments:
        print('The CornuCat launcher takes no parameters. Run ./packet-gen-dpdk and follow the prompts.', file=sys.stderr)
        return 2
    if not sys.platform.startswith('linux'):
        print('The CornuCat DPDK wizard requires Linux.', file=sys.stderr)
        return 1
    root = Path(__file__).resolve().parent.parent
    if os.geteuid() != 0:
        print('DPDK data-port access requires administrative privileges. Opening the system sudo prompt.', flush=True)
        try:
            os.execv('/usr/bin/sudo', ['sudo', '--', sys.executable, str(Path(__file__).resolve())])
        except OSError as error:
            print('Cannot request administrative access: ' + str(error), file=sys.stderr)
            return 1
    os.umask(0o077)
    prompt = Prompt(hostname=socket.gethostname())
    try:
        choose_backend(root)
        prompt.write('\nCornuCat | interactive DPDK setup')
        prompt.write('Raw UDP/TCP/ICMP streams, DPDK TCP connections, or validated PCAP replay.')
        prompt.write('The wizard uses a prepared data NIC and keeps each native mode separate.')
        config = prompt.configure(discover_devices(), sorted(os.sched_getaffinity(0)))
        if config is None:
            prompt.write('Cancelled. No traffic was started.')
            return 0
        return launch(config, prompt, root)
    except (KeyboardInterrupt, EOFError):
        prompt.write('\nCancelled. No traffic was started.')
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        prompt.write('Cannot run this session: ' + str(error))
        return 1


if __name__ == '__main__':
    sys.exit(main())
