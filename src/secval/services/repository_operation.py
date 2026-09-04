"""单进程仓库写操作协调，忙时不排队执行过时请求。"""

from contextlib import contextmanager


class RepositoryBusyError(ValueError):
    """已有上传或索引正在执行。"""


@contextmanager
def repository_operation(lock):
    if not lock.acquire(blocking=False):
        raise RepositoryBusyError("正在上传或建立索引，请等待当前操作完成后重试")
    try:
        yield
    finally:
        lock.release()
