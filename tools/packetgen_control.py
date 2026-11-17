#!/usr/bin/env python3
"""Control CornuCat through its private Unix SOCK_SEQPACKET socket.

Examples:
  sudo python3 tools/packetgen_control.py --socket /run/packetgen/control.sock status
  sudo python3 tools/packetgen_control.py --socket /run/packetgen/control.sock 'rate u 2000000'
  sudo python3 tools/packetgen_control.py --socket /run/packetgen/control.sock --watch

With no command, opens a prompt. Count commands set the lifetime accepted packet
target, not an additional packet budget; raising a completed target reactivates
that stream unless paused. This client never connects over a network or SSH.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import time

MAX_COMMAND = 1024
MAX_RESPONSE = 262144


def command_bytes(command):
    if not isinstance(command, str) or not command or len(command) > MAX_COMMAND:
        raise ValueError('Command must contain 1..1024 ASCII bytes')
    if any(ord(character) < 32 or ord(character) > 126 for character in command):
        raise ValueError('Command must be one printable ASCII line')
    return command.encode('ascii')


def request(path, command, timeout=3):
    payload = command_bytes(command)
    if not path.is_absolute():
        raise ValueError('Use an absolute path to the private control socket')
    if not hasattr(socket, 'SOCK_SEQPACKET') or not hasattr(socket, 'SO_PEERCRED') or not hasattr(os, 'geteuid'):
        raise RuntimeError('This client requires Linux Unix SOCK_SEQPACKET support')
    expected_uid = os.geteuid()
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError('Control endpoint must be owned by the current user with mode 0600')
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as stream:
        stream.settimeout(timeout)
        stream.connect(str(path))
        peer = stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
        _pid, uid, _gid = struct.unpack('3i', peer)
        if uid != expected_uid:
            raise RuntimeError('Control peer is not owned by the current user')
        if stream.send(payload) != len(payload):
            raise RuntimeError('Incomplete control command write')
        response, _ancillary, flags, _address = stream.recvmsg(MAX_RESPONSE)
        if flags & socket.MSG_TRUNC:
            raise RuntimeError('Control response exceeds the bounded client buffer')
    result = json.loads(response)
    if not isinstance(result, dict) or type(result.get('ok')) is not bool:
        raise RuntimeError('Control response is not a valid acknowledgement')
    return result


def show_response(document, compact=False):
    print(json.dumps(document, indent=None if compact else 2, separators=(',', ':') if compact else None), flush=True)


def interval(value):
    parsed = float(value)
    if not math.isfinite(parsed) or not 0.1 <= parsed <= 60:
        raise argparse.ArgumentTypeError('Watch interval must be 0.1..60 seconds')
    return parsed


def stream_key(item):
    return item.get('id'), item.get('name')


def rate_text(value):
    if value is None:
        return 'warming up'
    if value >= 1000000:
        return f'{value / 1000000:.3f} Mpps'
    return f'{value:,.0f} pps'


def render_watch(document, previous, elapsed, path):
    rows = document.get('streams')
    if not isinstance(rows, list):
        raise RuntimeError('Status acknowledgement has no stream list')
    print(f'CornuCat | {path.name} | {time.strftime("%H:%M:%S")}')
    print('Measured rates are sender accepted/submitted deltas; they are not receiver measurements.')
    print(f'{"NAME":<31} {"PROTO":<5} {"REQUESTED":>15} {"ACCEPTED RATE":>16} {"SUBMITTED / TARGET":>43} {"STATE":<10} TTL')
    current = {}
    for item in rows:
        if not isinstance(item, dict) or type(item.get('submitted')) is not int or item['submitted'] < 0:
            raise RuntimeError('Status contains invalid stream counters')
        key = stream_key(item)
        before = previous.get(key)
        rate = ((item['submitted'] - before) / elapsed
                if before is not None and elapsed > 0 and item['submitted'] >= before else None)
        current[key] = item['submitted']
        target = 'unlimited' if item.get('unlimited') else f'{item.get("pps", 0):,} pps'
        quota = item.get('quota', 0)
        counts = f'{item["submitted"]:,} / {quota:,}' if isinstance(quota, int) else f'{item["submitted"]:,} / {quota}'
        state = item.get('state') or ('paused' if item.get('paused') else 'complete' if item.get('complete') else 'running')
        print(f'{str(item.get("name", "?")):<31} {str(item.get("protocol", "?")):<5} '
              f'{target:>15} {rate_text(rate):>16} {counts:>43} {str(state):<10} '
              f'{item.get("ttl_min", "?")}..{item.get("ttl_max", "?")}')
    if not rows:
        print('(no active streams)')
    print('\nCtrl+C stops this display only; CornuCat continues. Use the stop command to stop it.')
    return current


def watch(path, seconds, compact=False):
    previous, last = {}, None
    while True:
        started = time.monotonic()
        document = request(path, 'status')
        sampled = time.monotonic()
        if not document['ok']:
            show_response(document, compact)
            return 1
        if compact:
            show_response(document, True)
        else:
            if sys.stdout.isatty():
                print('\033[2J\033[H', end='')
            previous = render_watch(document, previous, sampled - last if last is not None else 0, path)
        last = sampled
        time.sleep(max(0, seconds - (time.monotonic() - started)))


def interactive(path, compact=False):
    print('Commands: status; pause NAME; resume NAME; rate NAME PPS|unlimited; count NAME TOTAL;')
    print('          ttl NAME MIN MAX; add STREAMSPEC; remove NAME; stop. Local prompt: quit or exit.')
    print('Count TOTAL is the lifetime accepted target; it must be at least the already submitted total.')
    while True:
        try:
            command = input('cornucat> ').strip()
        except EOFError:
            return 0
        if command in ('quit', 'exit'):
            return 0
        if not command:
            continue
        try:
            document = request(path, command)
            show_response(document, compact)
            if command == 'stop' and document['ok']:
                return 0
        except (OSError, ValueError, RuntimeError) as error:
            print('Control command failed: ' + str(error), file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--socket', required=True, type=Path)
    parser.add_argument('--watch', nargs='?', const=1.0, type=interval, metavar='SECONDS')
    parser.add_argument('--interactive', action='store_true')
    parser.add_argument('--json', action='store_true', help='Compact JSON response (one per watch sample)')
    parser.add_argument('command', nargs='?', help='One quoted command; omitted for an interactive prompt')
    args = parser.parse_args(argv)
    if args.watch is not None and (args.interactive or args.command):
        parser.error('--watch cannot be combined with a command or --interactive')
    if args.interactive and args.command:
        parser.error('--interactive cannot be combined with a command')
    try:
        if args.watch is not None:
            return watch(args.socket, args.watch, args.json)
        if args.command is None:
            return interactive(args.socket, args.json)
        document = request(args.socket, args.command)
        show_response(document, args.json)
        return 0 if document['ok'] else 1
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print('Control command failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
