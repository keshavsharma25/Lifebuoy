class OPStackError(Exception):
    """Base Exception for OP Stack operations."""

    pass


class InvalidChainError(OPStackError):
    """Raised when an invalid chain is specified"""

    pass


class InvalidBlockNumber(OPStackError):
    """Raised when an invalid block number is specified"""

    pass


class OPPortalUnproven(OPStackError):
    """Raised when a withdrawal hash is not proven"""

    pass


class OPPortalInvalidProofTimstamp(OPStackError):
    """Raised when the proven timestamp is proven before the dispute game timestamp hence invalid."""

    pass


class OPPortalProofNotOldEnough(OPStackError):
    """Raised when the proof has not passed the deadline of 7 days"""

    pass


class OPPortalInvalidRootClaim(OPStackError):
    """Raised when the root claim is invalid"""

    pass
