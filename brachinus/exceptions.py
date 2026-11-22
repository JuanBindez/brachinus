class BrachinusError(Exception):
    """Base class for all brachinus errors."""


class InvalidKeyError(BrachinusError, ValueError):
    """The key, password or salt given is not usable."""


class FormatError(BrachinusError, ValueError):
    """The file is not a brachinus file or is structurally damaged."""


class DecryptionError(BrachinusError, ValueError):
    """Wrong password/key, or the data was modified or truncated."""
