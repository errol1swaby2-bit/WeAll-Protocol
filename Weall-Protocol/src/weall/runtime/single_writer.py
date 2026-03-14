import os
import sys
import fcntl


class SingleWriterLock:
    """
    Enforces a single-process writer for JSON-backed stores.
    Uses a filesystem lock. Safe for WSL + Linux.
    """

    def __init__(self, path: str):
        self.path = path
        self._fd = None

    def acquire(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._fd = open(self.path, "w")
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(
                f"[weall] ❌ single-writer lock already held: {self.path}",
                file=sys.stderr,
            )
            sys.exit(1)

    def release(self) -> None:
        if self._fd:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                self._fd.close()
                self._fd = None
