"""Private filesystem handling for SQLite databases containing sensitive data."""

from __future__ import annotations

import os
import stat
from pathlib import Path


_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")


def _require_private_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeError("SQLite storage directory cannot be securely inspected.") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
        or stat.S_IMODE(info.st_mode) & 0o700 != 0o700
    ):
        raise RuntimeError(
            "SQLite storage directory must be owned by the application user "
            "and accessible only to that user; secure it before startup."
        )


def _require_private_file(path: Path, require_private_mode: bool = True) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeError("SQLite data file cannot be securely inspected.") from exc
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        raise RuntimeError(
            "Existing SQLite data or journal files must be regular files owned "
            "by the application user."
        )
    if require_private_mode and (mode & 0o077 or mode & 0o600 != 0o600):
        raise RuntimeError(
            "Existing SQLite database files must be owned by the "
            "application user and have private read/write permissions; "
            "secure them before startup."
        )


def prepare_sqlite_path(database_path: Path) -> frozenset[Path]:
    """Create new SQLite storage privately; reject unsafe existing resources.

    Existing permissions are never changed. On Windows, POSIX mode checks are
    skipped and directory/file creation follows the platform defaults.
    """
    database_path = Path(database_path)
    directory = database_path.parent
    if os.name != "posix":
        directory.mkdir(parents=True, exist_ok=True)
        return frozenset()

    try:
        directory.parent.mkdir(parents=True, exist_ok=True)
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            _require_private_directory(directory)
        else:
            os.chmod(directory, 0o700)
    except RuntimeError:
        raise
    except OSError as exc:
        raise RuntimeError("SQLite storage directory could not be created securely.") from exc

    existing_sidecars: set[Path] = set()
    for suffix in _SIDECAR_SUFFIXES:
        sidecar = Path(str(database_path) + suffix)
        if os.path.lexists(sidecar):
            # The directory is mode 0700, so existing SQLite-created sidecars
            # cannot be reached by other users even if their file mode is wider.
            # Do not reject an in-flight journal created by another connection.
            _require_private_file(sidecar, require_private_mode=False)
            existing_sidecars.add(sidecar)

    if os.path.lexists(database_path):
        _require_private_file(database_path)
    else:
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(database_path, flags, 0o600)
        except FileExistsError:
            _require_private_file(database_path)
        except OSError as exc:
            raise RuntimeError("SQLite data file could not be created securely.") from exc
        else:
            try:
                os.fchmod(descriptor, 0o600)
            except OSError as exc:
                raise RuntimeError("SQLite data file permissions could not be secured.") from exc
            finally:
                os.close(descriptor)
    return frozenset(existing_sidecars)


def secure_new_sqlite_sidecars(database_path: Path, existing: frozenset[Path]) -> None:
    """Restrict only journal files newly created inside the private directory."""
    if os.name != "posix":
        return
    for suffix in _SIDECAR_SUFFIXES:
        sidecar = Path(str(database_path) + suffix)
        if sidecar in existing or not os.path.lexists(sidecar):
            continue
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(sidecar, flags)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RuntimeError("A newly created SQLite journal file cannot be secured.") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise RuntimeError("A newly created SQLite journal file has an unexpected owner or type.")
            os.fchmod(descriptor, 0o600)
        except OSError as exc:
            raise RuntimeError("A newly created SQLite journal file permissions could not be secured.") from exc
        finally:
            os.close(descriptor)
