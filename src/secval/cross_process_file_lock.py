"""提供一个简单的跨进程文件锁。"""

import os
from pathlib import Path


class CrossProcessFileLock:
    """在 Windows 开发机和 Linux 容器中使用同一个非阻塞锁接口。"""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def try_acquire(self):
        """立即尝试加锁；被其他进程占用时返回 None。"""
        handle = self.path.open("a+b")
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            # Windows 的字节锁至少需要文件中存在一个字节。
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            handle.close()
            return None
        return handle

    @staticmethod
    def release(handle):
        """释放锁并关闭对应文件句柄。"""
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
