#!/usr/bin/env python3
"""Run a verified ARM64 idmap parser in a bounded filesystem and syscall sandbox.

No Android services, device passthrough, or network sockets are provided. This is
only an offline parser invocation, not Android application/device execution.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import os
import resource
import subprocess
import tempfile
import time
from pathlib import Path

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def network_filter(fd):
    sec = ctypes.CDLL('libseccomp.so.2')
    sec.seccomp_init.argtypes = [ctypes.c_uint32]
    sec.seccomp_init.restype = ctypes.c_void_p
    sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    sec.seccomp_syscall_resolve_name.restype = ctypes.c_int
    sec.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    sec.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    sec.seccomp_release.argtypes = [ctypes.c_void_p]
    context = sec.seccomp_init(0x7fff0000)
    if not context:
        raise RuntimeError('seccomp context creation failed')
    denied = ['socket', 'socketpair', 'connect', 'bind', 'listen', 'accept', 'accept4',
              'sendmsg', 'recvmsg', 'sendmmsg', 'recvmmsg', 'sendto', 'recvfrom',
              'shutdown', 'getpeername', 'getsockname', 'setsockopt', 'getsockopt']
    try:
        for name in denied:
            number = sec.seccomp_syscall_resolve_name(name.encode())
            if number < 0 or sec.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0):
                raise RuntimeError('Cannot deny network syscall ' + name)
        if sec.seccomp_export_bpf(context, fd):
            raise RuntimeError('seccomp export failed')
    finally:
        sec.seccomp_release(context)
    os.lseek(fd, 0, os.SEEK_SET)
    return denied

def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (25, 30))
    # The unmodified Android linker reserves a large, sparse CFI shadow.
    # Bound virtual address space separately from the monitored resident limit.
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**3, 512 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024**2, 64 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

def process_tree_rss(pid):
    # This runtime hides /proc/PID/task/PID/children. Read namespace-local
    # status PPid fields instead so the QEMU grandchild is actually counted.
    processes = {}
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit():
            continue
        try:
            status = (directory / 'status').read_text()
            parent = rss = None
            for line in status.splitlines():
                if line.startswith('VmRSS:'):
                    rss = int(line.split()[1]) * 1024
                elif line.startswith('PPid:'):
                    parent = int(line.split()[1])
            processes[int(directory.name)] = (parent, rss or 0)
        except (FileNotFoundError, ProcessLookupError):
            pass
    seen = {pid}
    changed = True
    while changed:
        changed = False
        for current, (parent, _) in processes.items():
            if current not in seen and parent in seen:
                seen.add(current)
                changed = True
    return sum(processes.get(current, (None, 0))[1] for current in seen)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True, type=Path)
    parser.add_argument('--qemu-sha256', required=True)
    parser.add_argument('--android-root', required=True, type=Path)
    parser.add_argument('--idmap-relative', default='system/bin/idmap2')
    parser.add_argument('--idmap-sha256', required=True)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--guest-library-path', default='/android/system/lib64:/android/apex/com.android.runtime/lib64/bionic')
    parser.add_argument('idmap_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    qemu = args.qemu.resolve()
    android = args.android_root.resolve()
    idmap = (android / args.idmap_relative).resolve()
    if android not in idmap.parents or digest(qemu) != args.qemu_sha256 or digest(idmap) != args.idmap_sha256:
        raise ValueError('Path or immutable executable hash mismatch')
    inputs = args.inputs.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if output == android or android in output.parents or output == inputs or inputs in output.parents:
        raise ValueError('Output cannot be inside input trees')
    idmap_args = args.idmap_args
    if idmap_args and idmap_args[0] == '--':
        idmap_args = idmap_args[1:]
    if '--ignore-overlayable' in idmap_args:
        raise ValueError('Overlay policy bypass flags forbidden')
    with tempfile.TemporaryFile() as policy:
        denied = network_filter(policy.fileno())
        command = [
            '/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts',
            '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
            '--dir', '/tool', '--ro-bind', str(qemu), '/tool/qemu-aarch64',
            '--ro-bind', str(android), '/android', '--ro-bind', str(inputs), '/inputs',
            '--bind', str(output), '/output', '--tmpfs', '/tmp', '--proc', '/proc',
            '--dir', '/dev', '--ro-bind', '/dev/null', '/dev/null', '--ro-bind', '/dev/urandom', '/dev/urandom',
            '--chdir', '/output', '--setenv', 'PATH', '/usr/bin:/bin',
            '--seccomp', str(policy.fileno()), '--',
            '/tool/qemu-aarch64', '-R', '0', '-L', '/android',
            '-E', 'LD_LIBRARY_PATH=' + args.guest_library_path,
            '/android/' + args.idmap_relative,
        ] + idmap_args
        process = subprocess.Popen(command, pass_fds=(policy.fileno(),), preexec_fn=limits,
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        start = time.monotonic()
        peak_rss = 0
        termination = None
        while process.poll() is None:
            peak_rss = max(peak_rss, process_tree_rss(process.pid))
            if peak_rss > 512 * 1024**2:
                termination = 'resident_memory_limit'
            elif time.monotonic() - start > 45:
                termination = 'wall_time_limit'
            if termination:
                process.kill()
                break
            time.sleep(0.02)
        stdout, stderr = process.communicate(timeout=5)
        report = {'returncode': process.returncode, 'stdout': stdout, 'stderr': stderr,
                  'termination': termination, 'peak_sampled_tree_rss_bytes': peak_rss,
                  'elapsed_seconds': time.monotonic() - start}
    report.update({'command': command, 'qemu_sha256': args.qemu_sha256,
                   'idmap_sha256': args.idmap_sha256, 'denied_network_syscalls': denied,
                   'hardware_devices_provided': False, 'android_services_provided': False,
                   'input_trees_read_only': True, 'cpu_limit_seconds': [25, 30],
                   'address_space_limit_bytes': 512 * 1024**3, 'file_size_limit_bytes': 64 * 1024**2,
                   'resident_memory_limit_bytes': 512 * 1024**2, 'resident_poll_interval_seconds': 0.02,
                   'network_namespace_note': 'Network namespace initialization is denied by runtime NETLINK policy; seccomp denies all socket/network calls instead.'})
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
