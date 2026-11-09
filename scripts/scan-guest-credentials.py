"""Key-blind guest scans. Coverage failures are reported, never treated as passes."""
import hashlib
import os
import re
import stat

TOKENS = re.compile(rb"[A-Za-z0-9_-]{20,512}")


def stream_digests(stream, limit=0, size=None):
    """Return token hashes and bytes read; preserve candidates across reads."""
    digests, tail, count = set(), b"", 0
    while size is None or count < size:
        amount = min(1024 * 1024, size - count) if size is not None else 1024 * 1024
        if limit:
            amount = min(amount, limit - count)
        if amount <= 0:
            break
        chunk = stream.read(amount)
        if not chunk:
            break
        count += len(chunk)
        data = tail + chunk
        # Only finalize tokens with a known right boundary. A chunk boundary
        # must not create a digest for a partial token.
        cutoff = len(data)
        trailing = re.search(rb"[A-Za-z0-9_-]+$", data)
        if trailing:
            cutoff = trailing.start()
        digests.update(hashlib.sha256(m.group()).digest()[:8]
                       for m in TOKENS.finditer(data[:cutoff]))
        tail = data[cutoff:]
        # Limit the tail even for a large run of token characters. The
        # tokenizer's maximum candidate size is 512 bytes.
        while len(tail) > 512:
            digests.add(hashlib.sha256(tail[:512]).digest()[:8])
            tail = tail[512:]
    digests.update(hashlib.sha256(m.group()).digest()[:8] for m in TOKENS.finditer(tail))
    return digests, count


def credential_hits(needle, root="/"):
    if not needle:
        raise ValueError("empty credential: cannot check")
    skip = {os.path.join(root, name) for name in ("proc", "sys", "dev")}
    hits = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if os.path.join(directory, name) not in skip]
        for name in files:
            path = os.path.join(directory, name)
            if name == "ca.key":
                hits.add(path)
            try:
                # NONBLOCK prevents a file-type race from hanging on a FIFO;
                # fstat also excludes devices, sockets, and other special files.
                fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        continue
                    overlap = b""
                    while chunk := stream.read(1024 * 1024):
                        if needle in overlap + chunk:
                            hits.add(path)
                            break
                        overlap = chunk[-(len(needle) - 1):] if len(needle) > 1 else b""
            except (OSError, ValueError):
                pass
    return sorted(hits)


def ca_key_files(root="/"):
    """Find forbidden gateway CA key filenames without reading their contents."""
    skip = {os.path.join(root, name) for name in ("proc", "sys", "dev")}
    found = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if os.path.join(directory, name) not in skip]
        if "ca.key" in files:
            found.append(os.path.join(directory, "ca.key"))
    return sorted(found)


def token_digests(root="/", report=None):
    """Hash guest token candidates; no provider value or query enters the VM."""
    skip = {os.path.join(root, name) for name in ("proc", "sys", "dev")}
    digests = set()
    coverage = {"sources": 0, "bytes": 0, "unreadable": 0, "truncated": 0}
    if report is not None:
        report["filesystem"] = coverage
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if os.path.join(directory, name) not in skip]
        for name in files:
            try:
                fd = os.open(os.path.join(directory, name),
                             os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        continue
                    found, count = stream_digests(stream)
                    digests.update(found)
                    coverage["sources"] += 1
                    coverage["bytes"] += count
            except (OSError, ValueError):
                # Symlinks are deliberately excluded; an unreadable regular
                # file or a vanished file still leaves a coverage gap.
                if not os.path.islink(os.path.join(directory, name)):
                    coverage["unreadable"] += 1
    return digests


def extended_token_digests(root="/", report=None, memory_limit=0, disk_limit=0):
    """Scan files, process inputs, readable memory maps and whole block devices.

    Zero limits scan the entire source. Nonzero limits make a bounded triage
    possible, but every truncation/unreadable source is explicit. No key or
    digest-to-key query is supplied to the guest. Memory is a moving snapshot,
    not a proof of absence against a hostile kernel.
    """
    from pathlib import Path
    report = report if report is not None else {}
    for category in ("process_inputs", "process_memory", "block_devices"):
        report[category] = {"sources": 0, "bytes": 0, "unreadable": 0, "truncated": 0}
    found = token_digests(root, report)

    def scan(path, category, *, offset=0, size=None, limit=0, block=False):
        coverage = report[category]
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb", buffering=0) as stream:
                mode = os.fstat(stream.fileno()).st_mode
                if block and not stat.S_ISBLK(mode):
                    coverage["unreadable"] += 1
                    return
                if offset:
                    stream.seek(offset)
                digests, count = stream_digests(stream, limit, size)
                found.update(digests)
                coverage["sources"] += 1
                coverage["bytes"] += count
                if (size is not None and count < size) or (limit and count >= limit):
                    coverage["truncated"] += 1
        except (OSError, ValueError, OverflowError):
            coverage["unreadable"] += 1

    proc = Path(root) / "proc"
    for process in sorted(proc.glob("[0-9]*")):
        if not process.name.isdecimal():
            continue
        for name in ("environ", "cmdline"):
            scan(process / name, "process_inputs")
        try:
            maps = (process / "maps").read_text().splitlines()
        except OSError:
            report["process_memory"]["unreadable"] += 1
            continue
        remaining = memory_limit
        for line in maps:
            fields = line.split()
            if len(fields) < 2 or not fields[1].startswith("r"):
                continue
            try:
                start, end = (int(x, 16) for x in fields[0].split("-"))
            except ValueError:
                report["process_memory"]["unreadable"] += 1
                continue
            if memory_limit and remaining <= 0:
                report["process_memory"]["truncated"] += 1
                continue
            size = min(end-start, remaining) if memory_limit else end-start
            if size < end-start:
                report["process_memory"]["truncated"] += 1
            scan(process / "mem", "process_memory", offset=start, size=size)
            remaining -= size
    # sysfs enumerates actual block devices; never open character devices,
    # FIFOs, /dev/mem or /dev/random. No writes, mounts or fsck are performed.
    for device in sorted((Path(root) / "sys/class/block").glob("*")):
        scan(Path(root) / "dev" / device.name, "block_devices", limit=disk_limit, block=True)
    return found
