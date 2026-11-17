"""Own a group of independent F-Stack TCP processes on one prepared NIC.

Each process owns one stack and queue. The primary creates the shared DPDK
memory; secondaries attach to it. No device configuration or sysctl is changed.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

from native_sessions import _PREFIX, worker_session_command, worker_stack_configuration
from wizard_inputs import MAX_SESSION_WORKERS, UINT64_MAX

COUNTERS = ('attempted', 'connected', 'completed', 'failed', 'active', 'verified_bytes',
            'bytes_sent', 'bytes_received', 'rejected_peers', 'connect_errors', 'io_errors',
            'protocol_errors', 'timeouts', 'aborted')
FAILURES = ('connect_errors', 'io_errors', 'protocol_errors', 'timeouts', 'aborted')
PROFILE = ('role', 'fstack_commit', 'local_ip', 'peer_ip', 'port', 'payload_bytes')
TTL_PROFILE = ('ttl_min', 'ttl_max', 'ttl_policy', 'ttl_callback_active')
TTL_COUNTERS = ('ttl_selections', 'ttl_callback_errors')
TTL_FIELDS = (*TTL_PROFILE, *TTL_COUNTERS, 'ttl_histogram')


def _ttl_aggregate(documents):
    """Sum callback selections, never interpreting them as delivered packets.

    Legacy reports without any TTL fields retain their original schema. Once
    one worker publishes TTL metadata, every worker must supply the full
    matching policy and internally consistent unsigned counters/histogram.
    """
    if not any(any(key in row for key in TTL_FIELDS) for row in documents):
        return {}
    first = documents[0]
    for row in documents:
        if not all(key in row for key in TTL_FIELDS):
            raise ValueError('A TCP worker omitted part of its TTL report')
        low, high = row['ttl_min'], row['ttl_max']
        if (type(low) is not int or type(high) is not int or not 1 <= low <= high <= 255 or
                row['ttl_policy'] != 'per-packet' or type(row['ttl_callback_active']) is not bool or
                row['ttl_callback_active'] is not ((low, high) != (64, 64))):
            raise ValueError('Invalid TCP per-packet TTL policy or bounds')
        if any(row[key] != first[key] for key in TTL_PROFILE):
            raise ValueError('TCP workers use different TTL policies or bounds')
        if any(type(row[key]) is not int or not 0 <= row[key] <= UINT64_MAX for key in TTL_COUNTERS):
            raise ValueError('Invalid TCP TTL callback counters')
        histogram = row['ttl_histogram']
        if (not isinstance(histogram, list) or len(histogram) != 256 or
                any(type(value) is not int or not 0 <= value <= UINT64_MAX for value in histogram) or
                any(value for index, value in enumerate(histogram) if not low <= index <= high) or
                sum(histogram) != row['ttl_selections']):
            raise ValueError('TCP TTL histogram differs from its selections or configured range')
        if not row['ttl_callback_active'] and row['ttl_selections'] != 0:
            raise ValueError('Default TCP TTL has no callback selections')
    return {**{key: first[key] for key in TTL_PROFILE},
            **{key: sum(row[key] for row in documents) for key in TTL_COUNTERS},
            'ttl_histogram': [sum(row['ttl_histogram'][index] for row in documents) for index in range(256)],
            'ttl_measurement_scope': ('TX callback selections before PMD acceptance; retries may reselect. '
                                      'These are not delivered packet counts.')}


def _check_ttl_configuration(document, config):
    expected = (config.ttl_min, config.ttl_max)
    metadata = _ttl_aggregate([document])
    if metadata:
        if (metadata['ttl_min'], metadata['ttl_max']) != expected:
            raise RuntimeError('Native TCP TTL bounds differ from the reviewed configuration')
    elif expected != (64, 64):
        raise RuntimeError('Native TCP worker omitted the requested TTL policy')


def _child_setup(parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGINT, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(1)


def _read(path):
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None
    # The native engine reserves its exclusive output pathname before ff_init.
    # Its first atomic JSON publication happens only after stack setup. This
    # initial zero-byte reservation is pending status, not malformed JSON.
    return None if text == '' else json.loads(text)


def _write(path, data):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')
    os.replace(temporary, path)


def aggregate(documents, elapsed, state):
    if not documents or len(documents) > MAX_SESSION_WORKERS:
        raise ValueError('No TCP worker reports')
    if (type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0 or
            state not in ('running', 'quiescent', 'stopped')):
        raise ValueError('Invalid aggregate TCP state or elapsed time')
    for index, document in enumerate(documents):
        if (document.get('mode') != 'tcp-sessions' or document.get('backend') != 'f-stack'
                or type(document.get('worker_index')) is not int or document['worker_index'] != index
                or type(document.get('worker_count')) is not int
                or document['worker_count'] != len(documents) or document.get('coordinated') is not True):
            raise ValueError('Invalid TCP worker identity')
        if (document.get('role') not in ('client', 'server') or
                any(document.get(key) != documents[0].get(key) for key in PROFILE) or
                document.get('fstack_commit') != '761639943bdda33103aa98241ca6a3079f1c1b7e'):
            raise ValueError('TCP workers use different stack/role/payload profiles')
        if any(type(document.get(key)) is not int or document[key] < 0 for key in COUNTERS):
            raise ValueError('Invalid TCP worker counters')
        for key, low, high in (('connections', 1, 4294967295), ('concurrency', 1, 1024),
                               ('requested_cps', 0, 1000000000), ('payload_bytes', 1, 1400)):
            if type(document.get(key)) is not int or not low <= document[key] <= high:
                raise ValueError('Invalid TCP worker quota/rate/payload')
        if (document.get('state') not in ('waiting', 'running', 'draining', 'quiescent', 'stopped', 'error') or
                type(document.get('live_report_error')) is not bool):
            raise ValueError('Invalid TCP worker state')
        if (document['attempted'] != document['completed'] + document['failed'] + document['active'] or
                not document['completed'] <= document['connected'] <= document['attempted'] or
                document['verified_bytes'] != document['completed'] * document['payload_bytes'] or
                (document.get('state') != 'error' and
                 document['failed'] != sum(document[key] for key in FAILURES))):
            raise ValueError('Inconsistent TCP worker connection accounting')
        if (document['concurrency'] > document['connections'] or
                document['attempted'] > document['connections'] or
                document.get('unpaced') is not (document['requested_cps'] == 0)):
            raise ValueError('TCP worker exceeded a local quota or changed rate mode')
    if len({row['unpaced'] for row in documents}) != 1:
        raise ValueError('TCP workers mix maximum and paced rate modes')
    ttl = _ttl_aggregate(documents)
    totals = {key: sum(row[key] for row in documents) for key in
              (*COUNTERS, 'connections', 'concurrency', 'requested_cps')}
    if totals['connections'] > 4294967295 or totals['concurrency'] > 1024 or totals['requested_cps'] > 1000000000:
        raise ValueError('TCP workers exceed global quota/rate/concurrency limits')
    error = (any(row.get('state') == 'error' or row.get('live_report_error') for row in documents)
             or ttl.get('ttl_callback_errors', 0) != 0)
    return {'mode': 'tcp-sessions', 'backend': 'f-stack', 'role': documents[0]['role'],
            'tcp_role': documents[0]['role'], 'worker_count': len(documents),
            'fstack_commit': documents[0]['fstack_commit'], 'payload_bytes': documents[0]['payload_bytes'],
            'elapsed_seconds': elapsed, 'state': 'error' if error else state,
            'unpaced': documents[0]['unpaced'], 'live_report_error': error, **totals, **ttl}


class WorkerGroup:
    """Caller holds the NIC lock and owns this private report directory.

    Always close in a finally block. close() is idempotent, reaps every child,
    and keeps the primary alive until all secondaries have exited.
    """
    def __init__(self, binary, config, session):
        config.validate()
        self.binary, self.config, self.session = Path(binary), config, Path(session)
        if not _PREFIX.fullmatch(self.session.name):
            raise ValueError('TCP session basename is not a private namespace identifier')
        info = self.session.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('TCP report directory must be owned and private')
        if not set(config.worker_cores).issubset(os.sched_getaffinity(0)):
            raise ValueError('A selected TCP worker CPU is unavailable')
        self.children, self.handles, self.cpu_samples = [], [], []
        self.started = None
        self.closed = False
        self.runtime = {'shared_memory_mib': config.memory_mib, 'cpu_ids': list(config.worker_cores)}
        self.prefix = 'container-pg-tcp-' + self.session.name
        self.hugefiles = {}
        self.namespace_owned = False
        self.returncodes = []

    def _files(self):
        result = {}
        huge = Path('/dev/hugepages')
        if not huge.exists():
            return result
        # DPDK's file-prefix is followed directly by map_<number>. Match that exact
        # namespace; never remove arbitrary hugepages or another run's files.
        for path in huge.glob(self.prefix + 'map_*'):
            info = path.lstat()
            suffix = path.name[len(self.prefix + 'map_'):]
            if not suffix.isdecimal() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise RuntimeError('Unexpected shared hugepage file')
            result[path] = (info.st_dev, info.st_ino)
        return result

    def start(self):
        if self.children or self.closed:
            raise RuntimeError('TCP worker group cannot be restarted')
        if self._files():
            raise RuntimeError('TCP shared memory namespace already exists')
        self.namespace_owned = True
        ini = self.session / 'fstack.ini'
        with ini.open('x') as stream:
            stream.write(worker_stack_configuration(self.config, self.session))
        commands = []
        try:
            for index in range(len(self.config.worker_cores)):
                directory = self.session / ('worker-' + str(index))
                directory.mkdir(mode=0o700)
                command = worker_session_command(self.binary, self.config, ini,
                    directory / 'source.json', directory / 'live.json', index)
                commands.append(command)
                out = (directory / 'engine.stdout.log').open('x')
                self.handles.append(out)
                err = (directory / 'engine.stderr.log').open('x')
                self.handles.append(err)
                parent = os.getpid()
                child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out,
                    stderr=err, cwd=self.session, close_fds=True,
                    start_new_session=True, shell=False,
                    preexec_fn=lambda: _child_setup(parent))
                self.children.append(child)
                deadline = time.monotonic() + 20
                while True:
                    if child.poll() is not None:
                        raise RuntimeError(f'TCP worker {index} exited during startup; see its engine.stderr.log')
                    document = _read(directory / 'live.json')
                    if document is not None and document.get('state') == 'waiting':
                        _check_ttl_configuration(document, self.config)
                        if (document.get('worker_index') != index or
                                document.get('worker_count') != len(self.config.worker_cores)):
                            raise RuntimeError('TCP worker startup identity mismatch')
                        break
                    if time.monotonic() > deadline:
                        raise RuntimeError(f'TCP worker {index} did not become ready')
                    time.sleep(0.025)
            self.hugefiles = self._files()
            self.runtime['processes'] = [self._runtime(child.pid) for child in self.children]
            self.runtime['hugepage_files'] = len(self.hugefiles)
            self.cpu_samples.append(self._cpu())
            self.started = time.monotonic()
            for child in self.children:
                child.send_signal(signal.SIGUSR1)
            _write(self.session / 'configuration.json', {'commands': commands,
                'engine_sha256': hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                'shared_memory_mib': self.config.memory_mib,
                'note': 'One independent TCP stack per CPU; one shared DPDK memory pool.'})
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _runtime(pid):
        process = Path('/proc', str(pid))
        threads = []
        for task in (process / 'task').iterdir():
            threads.append({'tid': int(task.name), 'allowed_cpus': sorted(os.sched_getaffinity(int(task.name))),
                            'comm': (task / 'comm').read_text().strip()})
        huge = []
        for line in (process / 'maps').read_text().splitlines():
            if '/dev/hugepages/' in line:
                fields = line.split()
                huge.append({'device': fields[3], 'inode': int(fields[4]), 'path': fields[-1]})
        return {'pid': pid, 'threads': threads, 'hugepage_mappings': huge}

    def _cpu(self):
        before = time.monotonic_ns()
        ticks = {}
        for index, child in enumerate(self.children):
            fields = Path('/proc', str(child.pid), 'stat').read_text().rsplit(')', 1)[1].split()
            ticks[str(index)] = int(fields[11]) + int(fields[12])
        vm = next(line.split()[1:9] for line in Path('/proc/stat').read_text().splitlines()
                  if line.startswith('cpu '))
        return {'observed_monotonic_ns': (before + time.monotonic_ns()) // 2,
                'clock_ticks': os.sysconf('SC_CLK_TCK'), 'process_cpu_ticks': ticks,
                'vm_cpu': list(map(int, vm))}

    def sample(self):
        if self.started is None or self.closed:
            raise RuntimeError('TCP workers are not running')
        self.cpu_samples.append(self._cpu())
        for index, child in enumerate(self.children):
            if child.poll() is not None:
                raise RuntimeError(f'TCP worker {index} exited unexpectedly; see its engine.stderr.log')
        documents = [_read(self.session / f'worker-{i}/live.json') for i in range(len(self.children))]
        if any(row is None for row in documents):
            raise RuntimeError('A TCP worker stopped publishing status')
        if any(row.get('state') in ('error', 'io-error') or row.get('live_report_error')
               for row in documents):
            raise RuntimeError('A TCP worker reported a runtime error; see its reports')
        state = 'quiescent' if all(row['state'] == 'quiescent' for row in documents) else 'running'
        document = aggregate(documents, time.monotonic() - self.started, state)
        document['stale'] = any(time.time() - (self.session / f'worker-{i}/live.json').stat().st_mtime > 3
                                for i in range(len(documents)))
        _write(self.session / 'live.json', document)
        return document

    def quiescent(self):
        return self.sample()['state'] == 'quiescent'

    def close(self):
        if self.closed:
            return
        old_mask = (signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGHUP})
                    if hasattr(signal, 'pthread_sigmask') else None)
        old = None
        handler_installed = False
        errors = []
        try:
            old = signal.signal(signal.SIGINT, signal.SIG_IGN)
            handler_installed = True
            # Never let primary EAL cleanup race a secondary's live mappings.
            def stop_child(child, interrupt_sent=False):
                if child.poll() is not None:
                    return
                for phase, (action, timeout) in enumerate(((lambda: child.send_signal(signal.SIGINT), 7),
                                                         (child.terminate, 2), (child.kill, 2))):
                    if phase != 0 or not interrupt_sent:
                        try:
                            action()
                        except ProcessLookupError:
                            pass
                        except OSError as error:
                            errors.append(type(error).__name__ + ': failed to signal an owned TCP worker')
                    try:
                        child.wait(timeout=timeout)
                        return
                    except subprocess.TimeoutExpired:
                        continue
                    except OSError as error:
                        errors.append(type(error).__name__ + ': failed to reap an owned TCP worker')
                if child.poll() is None:
                    errors.append('Owned TCP worker remained alive after bounded SIGKILL wait')
            # Start every secondary's bounded TCP drain before waiting for
            # any one of them. The primary remains untouched until all those
            # contexts have exited, including timeout/error escalation paths.
            secondaries = list(reversed(self.children[1:]))
            interrupted_secondaries = set()
            for child in secondaries:
                if child.poll() is not None:
                    continue
                try:
                    child.send_signal(signal.SIGINT)
                    interrupted_secondaries.add(id(child))
                except ProcessLookupError:
                    interrupted_secondaries.add(id(child))
                except OSError as error:
                    errors.append(type(error).__name__ + ': failed to interrupt an owned TCP secondary')
            for child in secondaries:
                stop_child(child, id(child) in interrupted_secondaries)
            if any(child.poll() is None for child in self.children[1:]):
                raise RuntimeError('Critical TCP cleanup failure: secondary still alive; primary kept running')
            if self.children:
                stop_child(self.children[0])
            self.returncodes = [child.returncode for child in self.children]
            if any(child.poll() is None for child in self.children):
                raise RuntimeError('Critical TCP cleanup failure: owned worker still alive')
            self.closed = True
            # This namespace was absent before start, and is owned by this
            # group. Record inodes before unlinking after every child is reaped.
            files = self._files() if self.namespace_owned else {}
            for path, identity in files.items():
                info = path.lstat()
                if ((info.st_dev, info.st_ino) != identity or
                        path in self.hugefiles and self.hugefiles[path] != identity):
                    raise RuntimeError('Shared hugepage file changed during cleanup')
                path.unlink()
            self.runtime['removed_hugepage_files'] = len(files)
        finally:
            try:
                if self.closed:
                    for handle in self.handles:
                        try:
                            handle.close()
                        except OSError as error:
                            errors.append(type(error).__name__ + ': failed to close an owned TCP log')
            finally:
                try:
                    if handler_installed:
                        signal.signal(signal.SIGINT, old)
                finally:
                    # A queued TERM/HUP may invoke the caller's handler when
                    # unblocked, after owned children and handles are cleaned.
                    if old_mask is not None:
                        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        if errors:
            raise RuntimeError('; '.join(errors))

    def report(self):
        if not self.closed:
            raise RuntimeError('Stop TCP workers before reading final reports')
        workers = [_read(self.session / f'worker-{i}/source.json') for i in range(len(self.children))]
        if len(workers) != len(self.config.worker_cores) or any(row is None for row in workers):
            raise RuntimeError('A TCP worker has no final report')
        result = aggregate(workers, time.monotonic() - self.started if self.started else 0, 'stopped')
        result.update({'role': 'sender' if self.config.role == 'client' else 'receiver',
                       'workers': workers, 'cpu_samples': self.cpu_samples,
                       'runtime': self.runtime, 'returncodes': self.returncodes})
        _write(self.session / 'source.json', result)
        return result


def owned_multi_run(binary, config, session, prompt):
    group = WorkerGroup(binary, config, session)
    previous = None
    cancelled = False
    next_display = 0
    try:
        group.start()
        prompt.write(f'Started {len(config.worker_cores)} native TCP workers; {config.memory_mib} MiB shared. Ctrl+C stops all workers.')
        while True:
            document = group.sample()
            if time.monotonic() >= next_display:
                elapsed = document['elapsed_seconds']
                cps = (document['completed'] - previous['completed']) / (elapsed - previous['elapsed_seconds']) if previous else 0
                prompt.write(f"TCP {config.role} | {len(config.worker_cores)} workers | "
                    f"{cps:,.0f} completed connections/s | active {document['active']} | "
                    f"completed {document['completed']:,} | failed {document['failed']:,}" +
                    (' | status stale' if document['stale'] else ''))
                previous, next_display = document, time.monotonic() + 1
            if document['state'] == 'quiescent':
                break
            import select
            import sys
            readable, _, _ = select.select([sys.stdin], [], [], 0.05)
            if readable and sys.stdin.readline() == '':
                raise EOFError
    except (KeyboardInterrupt, EOFError):
        cancelled = True
        prompt.write('Stopping TCP workers and draining their connections...')
    finally:
        group.close()
        prompt.write('Reports: ' + str(session))
    report = group.report()
    prompt.write(f"Completed {report['completed']:,}; failed {report['failed']:,}; "
                 'completed means verified echo and orderly receive EOF.')
    if not cancelled and (any(group.returncodes) or report['failed']):
        raise RuntimeError('Native TCP session reported failures; see source.json and worker logs.')
    return 0
