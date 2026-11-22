
import base64
import contextlib
import os
import tempfile
import warnings

from brachinus.exceptions import *


def _resolve_remove(remove_original, backup):
    """`backup` is the old, deprecated spelling: backup=True keeps the original."""
    if backup is None:
        return bool(remove_original)

    warnings.warn(
        "'backup' is deprecated; use remove_original (backup=True means "
        "remove_original=False)",
        DeprecationWarning,
        stacklevel=3,
    )
    return not backup


def _check_name(name):
    if (
        not isinstance(name, str)
        or name in ("", ".", "..")
        or "/" in name
        or "\\" in name
        or "\x00" in name
    ):
        raise DecryptionError("decrypted name is not a safe file name")

    return name


def _b64e(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text):
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as e:
        raise FormatError(f"invalid encrypted name: {e}") from e


@contextlib.contextmanager
def _atomic_write(path, mode):
    """Write to a temp file next to `path`, fsync, then rename into place."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".brachinus-", suffix=".tmp", dir=parent)

    try:
        with os.fdopen(fd, "wb") as f:
            yield f
            f.flush()
            os.fsync(f.fileno())

        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)

        raise


def _default_mode():
    mask = os.umask(0)
    os.umask(mask)
    return 0o666 & ~mask


def _prune_empty_dirs(root):
    for cur, _dirs, _files in os.walk(root, topdown=False):
        with contextlib.suppress(OSError):
            os.rmdir(cur)
