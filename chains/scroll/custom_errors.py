from typing import Optional


class ScrollError(Exception):
    """Base Exception for Scroll Stack operations."""

    def __init__(self, message: str, original_error: Optional[Exception] = None):
        super().__init__(message)
        self.original_error = original_error


class GasEstimationError(ScrollError):
    """Exception while estimating gas."""

    pass


class EventParseError(ScrollError):
    """Exception in case transaction doesn't emit the event"""

    pass


class UnprovenError(ScrollError):
    """Raises Exception when batch is yet to proven hence withdrawals cannot be performed on L1"""

    pass
