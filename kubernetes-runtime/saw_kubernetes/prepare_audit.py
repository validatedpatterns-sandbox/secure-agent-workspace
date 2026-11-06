"""Seal the workspace's dedicated, pre-mounted audit file on a Linux filesystem."""
import array
import fcntl
import os
import stat
import sys

# linux/fs.h defines the argument type as long, including on 64-bit Linux.
LONG_SIZE = array.array("l").itemsize
FS_IOC_GETFLAGS = 0x80006601 | (LONG_SIZE << 16)
FS_IOC_SETFLAGS = 0x40006602 | (LONG_SIZE << 16)
FS_APPEND_FL = 0x20


def prepare(root):
    directory = os.open(root, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open("tool-actions.jsonl", os.O_APPEND | os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
                     | os.O_NONBLOCK, 0o600, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
                raise RuntimeError("audit target requires a single regular file owned by the workspace UID")
            flags = array.array("l", [0])
            fcntl.ioctl(fd, FS_IOC_GETFLAGS, flags, True)
            if not flags[0] & FS_APPEND_FL:
                if info.st_size:
                    raise RuntimeError("refusing to adopt a nonempty unsealed log")
                flags[0] |= FS_APPEND_FL
                fcntl.ioctl(fd, FS_IOC_SETFLAGS, flags)
            fcntl.ioctl(fd, FS_IOC_GETFLAGS, flags, True)
            if not flags[0] & FS_APPEND_FL:
                raise RuntimeError("filesystem failed to seal the log")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory)
    finally:
        os.close(directory)


if __name__ == "__main__":
    root = sys.argv[1]
    os.makedirs(root, mode=0o750, exist_ok=True)
    prepare(root)
    print("audit inode is append-only")
