"""Jebena Client for the Jebena GraphQL API Server."""

# We've intentionally designed the package namespace to be equal
# to the single jebenaclient.py file, so that "quick and dirty" work
# can snag the .py file directly and import it, with the same interface.

from .jebenaclient import (  # noqa: F401
    __version__,
    JebenaCliException,
    JebenaCliGQLException,
    JebenaCliGQLPermissionDenied,
    JebenaCliMissingKeyException,
    run_query,
    get_last_run_trace_id,
)

__all__ = [
    'run_query',
    'get_last_run_trace_id',
]
