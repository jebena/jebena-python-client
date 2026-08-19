#!/usr/bin/env python3  # noqa -- the hash-bang line here allows for direct script execution

"""
A very simple GQL Client for the Jebena API Server.

Key features:
  * Support for usage via both command-line and python import
  * Request timeout and request retry handling

The simplest way to run the client is to directly run python:
    1. Set up your ENV variables with JEBENA_API_KEY_NAME,
       JEBENA_API_SECRET_KEY, and JEBENA_API_ENDPOINT.
    2. python ./jebenaclient.py
    3. Enter your GQL query as prompted.

You can also use this script directly in Python:
    from jebenaclient import run_query
    gql_query_string = "query { me { person { displayName } } }"
    run_query(gql_query_string)

Variables can be passed in as well:
    from jebenaclient import run_query
    run_query(gql_query_string, variables=...)

When running in Python, we recommend setting the operation_name for logging:
   run_query(gql_query_string, operation_name="fetch_display_name")

For GQL Schema help, see documentation on the Jebena API Server
by visiting (using a web browser) the API endpoint you are using.

Example of a simple GQL query:
    query { me { person { displayName } } }

Queries with variables are also supported by "wrapping" your query like so:
{
    "query": "query { me { person { displayName } } }",
    "variables": {"foo": "bar"}
}

Or, with an operation name:
{
    "query": "query operationName { me { person { displayName } } }",
    "variables": {"foo": "bar"},
    "operationName": "getDisplayName"
}

For developers, the Jebena Trace ID for the most recent call to run_query()
is available by calling get_last_run_trace_id()
"""

# Version history:
# 0.1.0  20191121: Quick initial implementation, to get things rolling.
# 0.2.0  20200222: Better error handling and python clean-up.
# 0.3.0  20200409: Minor updates to include version number in user-agent
#                  and script timeout.
# 0.4.0  20200719: Minor logging / timeout changes for rate limiting;
#                  flake8 fixes.
# 0.5.0  20200825: Updates for splitting jebena_cli.py into a stand-alone package.
# 0.6.0  20201030: Various small fixes, including multi-line
#                  support of wrapped queries.
# 0.7.0  20201221: Address issues as flagged in GH (don't retry mutations;
#                  better error handling).
# 0.7.1  20210128: Address socket timeout issue.
# 0.8.0  20210204: Make script Python 2.7 compatible.
# 0.8.1  20210217: Handle some flake8 / mypy issues in a Py 2.7 compatible way.
# 0.8.2  20210302: Add support for GQL "operationName" parameter
# 0.8.5  20210316: More fixes for Python 2.7
# 0.8.6  20210318: Expose retry logic for mutations for developers
# 0.8.7  20210517: Fix for spurious warning in Python2 setups for logging
# 0.9.0  20210806: Add get_last_run_trace_id() call;
#                  re-work python logging setup for py2 issue
# 0.9.1  20210813: Re-work logger to add NullHandler for py2 reasons
# 0.9.2  20230222: Improve timeout handling error messages, for clarity
# 0.9.3  20240923: Add timeout and hint on socket error, for more clarity on timeout cases
# 0.10.0 20260818: Drop Python 2.7 support (Python 3.8+ only); retry mutations on
#                  a refused connection; move packaging to pyproject.toml;
#                  send GQL "variables" as a map; quieter HTTP error logging.
__version__ = "0.10.0"

import errno
import json
import logging
import os
import pprint
import socket
import ssl
import sys
import time
from http.client import HTTPException, RemoteDisconnected
from json import JSONDecodeError
from threading import Timer
from typing import NoReturn, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

LOGGER = logging.getLogger(__name__)
__JEBENA_TRACE_ID_OF_LAST_RUN_QUERY = None  # See get_last_run_trace_id()
__MAX_RUN_TIME_IN_SECONDS = 60 * 5
if os.getenv('JEBENA_CLIENT_TIMEOUT'):
    __MAX_RUN_TIME_IN_SECONDS = int(os.getenv('JEBENA_CLIENT_TIMEOUT'))


class JebenaCliException(Exception):
    """Generic client error, indicating an issue with the connection or setup."""


class JebenaCliGQLException(JebenaCliException):
    """GQL-specific error, raised when the server response indicates a bad query."""


class JebenaCliMissingKeyException(JebenaCliException):
    """Raised when client credentials are missing or the user is invalid."""


class JebenaCliGQLPermissionDenied(JebenaCliException):
    """Raised when the user does not have sufficient server permissions for the query."""


def run_query(
        query: str,
        operation_name: Optional[str] = None,
        variables: Optional[dict] = None,
        api_endpoint: Optional[str] = None,
        api_key_name: Optional[str] = None,
        api_secret_key: Optional[str] = None,
        allow_insecure_https: bool = False,
        allow_retries_on_mutations: bool = False,
        return_instead_of_raise_on_errors: bool = False,
        skip_logging_transient_errors: bool = False
) -> dict:
    """Send a GQL query to the Jebena API Server and return the server reply.

    OS Environ variables should be set for JEBENA_API_KEY_NAME, JEBENA_API_SECRET_KEY,
    and JEBENA_API_ENDPOINT, taking care to keep the secret key secured. Alternatively,
    those values can be passed to this function.

    :param query: GQL query string to run.

    :param operation_name: (Optional) A name for the GQL operation; useful for logging / debugging.

    :param variables: Key-value dictionary of variables for query.

    :param api_endpoint: The URL of your Jebena API server. When not passed, the
    ENV variable JEBENA_API_ENDPOINT is accessed.

    :param api_key_name: Your Jebena API key name. When not passed, the
    ENV variable JEBENA_API_KEY_NAME is accessed. This value is not sensitive.

    :param api_secret_key: The secret key associated with your API key name.
    When not passed, ENV variable JEBENA_API_SECRET_KEY is read. This value must
    be kept securely stored!

    :param allow_insecure_https: When true, allow self-signed SSL certificates.
    For localhost-based endpoints, this will automatically flip to True.

    :param allow_retries_on_mutations: When true, any mutation-based query that
    fails due to non-GQL errors will be retried. This should only be enabled for
    idempotent mutations; there is no guarantee that the server did NOT process the request.

    :param return_instead_of_raise_on_errors: When true, return the GQL response
    and assume that the caller will inspect for errors, instead of raising.

    :param skip_logging_transient_errors: When true, skip emitting logger statements
    that are redundant with exceptions being raised. This may be useful in certain
    automated cases.

    :return: GQL response as a Python dict
    """
    # Avoid a condition where an empty query silently returns nothing:
    if not query or not query.strip():
        raise JebenaCliGQLException("Empty query.")

    # When API parameters aren't passed in, fall back on loading from environment:
    try:
        if not api_endpoint:
            api_endpoint = os.environ["JEBENA_API_ENDPOINT"]
        if not api_key_name:
            api_key_name = os.environ["JEBENA_API_KEY_NAME"]
        if not api_secret_key:
            api_secret_key = os.environ["JEBENA_API_SECRET_KEY"]
    except KeyError:
        # Then ENV vars are missing. We pause here for a brief sleep in case this script
        # is using this script in a bash loop, which prevents a spin condition we've seen:
        time.sleep(0.5)
        raise JebenaCliMissingKeyException(
            "Error: missing JEBENA variables. "
            "Make sure that your Jebena API keys are defined in your shell:\n"
            "  export JEBENA_API_KEY_NAME=jeb00000...\n"
            "  export JEBENA_API_SECRET_KEY=<sensitive>\n"
            "  export JEBENA_API_ENDPOINT=https://api-hostname.example.com/v1/\n\n"
            "Reminder: never store your API keys under dot-files like ~/.profile. "
            "Instead, store keys in an encrypted disk image or volume, "
            "and then in your active shell, run 'source /path/to/secure-keys.env'."
        )

    # Make sure our API endpoint ends with the expected trailing slash:
    if api_endpoint[-1] != "/":
        raise JebenaCliException("JEBENA_API_ENDPOINT missing trailing slash")

    # Always allow insecure connections when connecting to localhost:
    is_api_endpoint_public = False
    try:
        parsed_uri = urlparse(api_endpoint)
        addresses = socket.getaddrinfo(parsed_uri.hostname, None)
        for address in addresses:
            if address[4][0] not in ("::1", "127.0.0.1", "fe80::1", "fe80::1%lo0"):
                is_api_endpoint_public = True
    except Exception as exc:
        raise JebenaCliException(
            "Unable to find Jebena API Server at endpoint '%s' (%s)" % (api_endpoint, exc)
        )
    if not is_api_endpoint_public:
        allow_insecure_https = True

    if not variables:
        # See if our query has variables directly defined in it;
        # that is, we support two input formats:
        # Direct:   {query}
        # Wrapped:   {"query": query; "variables": {variables...}}
        try:
            wrapped_query = json.loads(query)
            LOGGER.debug("Parsing wrapped query")
            if "query" in wrapped_query:
                query = wrapped_query["query"]
            if "variables" in wrapped_query:
                variables = wrapped_query["variables"]
            if "operationName" in wrapped_query:
                operation_name = wrapped_query["operationName"]
        except (JSONDecodeError, TypeError):
            # Not a wrapped query (or not a JSON object); use the input as a plain query.
            pass

    parsed_response = _execute_gql_query(
        api_endpoint,
        query,
        operation_name=operation_name,
        variables=variables,
        allow_insecure_https=allow_insecure_https,
        api_key_name=api_key_name,
        api_secret_key=api_secret_key,
        allow_retries_on_mutations=allow_retries_on_mutations,
        skip_logging_transient_errors=skip_logging_transient_errors
    )

    if not return_instead_of_raise_on_errors:
        pp = pprint.PrettyPrinter(indent=4)

        if "errors" in parsed_response:
            exception_type = JebenaCliGQLException
            LOGGER.error(
                "GQL response includes an error. Part of the query may have succeeded.\n"
                " *** The original query was:\n%s\n\n"
                " *** The full response was:\n%s\n\n",
                pp.pformat(query),
                pp.pformat(parsed_response)
            )
            error_messages = []
            error_count = 0
            for error in parsed_response["errors"]:
                error_count += 1
                error_messages.append(error["message"])
                if "errorType" in error and error["errorType"] == "permissionDenied":
                    exception_type = JebenaCliGQLPermissionDenied
                LOGGER.error(
                    " *** GQL error #%s: %s\n",
                    error_count,
                    error["message"].rstrip()
                )
            LOGGER.error("For GraphQL schema, see Docs tab at %sdocs/graphiql", api_endpoint)
            raise exception_type(
                "GQL errors encountered (%s)" % '; '.join(error_messages)[0:512]
            )

    # Return GQL response:
    return parsed_response


def get_last_run_trace_id() -> Optional[str]:
    """
    Return the Jebena API Server's trace id for the last call to run_query().

    This trace id can be used by developers to query the server's logging
    system for details about what actions the backend performed.

    :return: Most recent call to run_query()'s trace id
    """
    return __JEBENA_TRACE_ID_OF_LAST_RUN_QUERY


def _is_query_a_mutation(query: str) -> bool:
    """Return True when the given GQL query is a mutation.

    Mutations are not retried by default, so err on the side of calling
    something a mutation: 'mutation{...}' with no separating whitespace
    must be caught just as surely as 'mutation { ... }'.
    """
    stripped_query = query.lstrip()
    if not stripped_query.lower().startswith("mutation"):
        return False
    remainder = stripped_query[len("mutation"):]
    # A bare "mutation" is the whole query; otherwise the next character has to be a
    # separator (whitespace, '{', or the '(' of a variable list) rather than part of a
    # longer word, so that a query named e.g. "query mutationsById {...}" isn't matched.
    return not remainder or not (remainder[0].isalnum() or remainder[0] == "_")


def _is_connection_refused(exc: URLError) -> bool:
    """Return True when a URLError was caused by the connection being refused.

    ECONNREFUSED means the peer answered our TCP SYN with a RST: no socket was
    ever opened and no bytes were ever sent, so the request provably did not run.
    """
    reason = getattr(exc, "reason", None)
    if isinstance(reason, socket.gaierror):
        # DNS failures carry EAI_* codes in .errno, which share a number space
        # with the errno codes we're testing for here. Never confuse the two.
        return False
    return getattr(reason, "errno", None) == errno.ECONNREFUSED


def _execute_gql_query(
        api_endpoint: str,
        query: str,
        operation_name: Optional[str] = None,
        variables: Optional[dict] = None,
        allow_insecure_https: bool = False,
        api_key_name: Optional[str] = None,
        api_secret_key: Optional[str] = None,
        retries_allowed: int = 2,
        allow_retries_on_mutations: bool = False,
        skip_logging_transient_errors: bool = False
) -> dict:
    """Send a GQL query to the server and return the GQL response."""
    if not api_key_name:
        raise JebenaCliMissingKeyException(
            "Missing API Key Name (Try setting ENV variable JEBENA_API_KEY_NAME)"
        )
    if not api_secret_key:
        raise JebenaCliMissingKeyException(
            "Missing API Secret Key (Try setting ENV variable JEBENA_API_SECRET_KEY)"
        )
    if variables is None:
        # NB: GQL defines "variables" as a map; an empty list here is invalid per spec
        # and only ever worked because the server tolerated it.
        variables = {}
    data = {
        "query": query,
        "variables": variables,
    }
    if operation_name:
        data["operationName"] = operation_name
    headers = {
        "Accept": "application/json",
        "Authorization":  "ApiKey %s/%s" % (api_key_name, api_secret_key),
        "Content-Type": "application/json",
        "User-Agent": "jebena-cli-tool/%s" % __version__,
    }
    is_query_a_mutation = _is_query_a_mutation(query)
    try:
        request_payload = json.dumps(data).encode("utf-8")
    except TypeError as exc:
        raise JebenaCliException("Invalid input (unable to create JSON; %s)" % exc)

    # Ensure our endpoint is not a file:/ path:
    if api_endpoint[0:4].lower() != "http":
        raise JebenaCliException("Invalid API Endpoint %s" % api_endpoint)
    # By convention, our gql access point is under a sub-path of the API endpoint:
    gql_endpoint = "%sgql/" % api_endpoint
    LOGGER.debug("Request URL: %s", gql_endpoint)
    LOGGER.debug("Request body:\n%s\n", request_payload)
    req = Request(
        gql_endpoint,
        data=request_payload,
        headers=headers
    )

    # Send and return response -- with a short retry / delay loop for non-mutation
    # queries to give some support to network hiccups, server rate-limiting, or
    # individual backend-node issues.
    if is_query_a_mutation and not allow_retries_on_mutations:
        attempts_allowed = 1
    else:
        attempts_allowed = 1 + retries_allowed
    # NB: attempts_allowed may be raised mid-loop; see the URLError handler below.
    attempts_tried = 0
    retry_delay_constant_delay = 5
    retry_delay_next_attempt_extra_delay = 0
    retry_delay_factor = 3

    def _log_and_raise_or_retry(log_message: str, *args: object) -> None:
        """Log error and either return if retries allowed or raise."""
        if attempts_tried < attempts_allowed:
            if not skip_logging_transient_errors:
                LOGGER.warning(log_message, *args)
            return
        _log_and_raise(log_message, *args)

    def _log_and_raise(log_message: str, *args: object) -> NoReturn:
        """Log error and raise now."""
        if not skip_logging_transient_errors:
            LOGGER.error(log_message, *args)
        raise JebenaCliException(log_message % args)

    while attempts_tried < attempts_allowed:
        attempts_tried += 1
        LOGGER.debug("Sending query; attempt %s of %s", attempts_tried, attempts_allowed)
        if attempts_tried > 1:
            # When re-attempting query, issue a warning and wait a bit before retrying:
            retry_delay = retry_delay_constant_delay + \
                          retry_delay_next_attempt_extra_delay + \
                          retry_delay_factor ** attempts_tried
            retry_delay_next_attempt_extra_delay = 0
            if not skip_logging_transient_errors:
                LOGGER.warning(
                    "Jebena client failed to fetch from %s; retry in %s seconds; %s attempts left.",
                    api_endpoint,
                    retry_delay,
                    (attempts_allowed - attempts_tried + 1)  # We're after the += 1 above
                )
            time.sleep(retry_delay)

        start_time = time.time()
        try:
            context = None
            if allow_insecure_https:
                # Accept self-signed or mismatched certificates (localhost / dev endpoints):
                context = ssl.create_default_context()
                context.check_hostname = False  # Must be cleared before setting CERT_NONE.
                context.verify_mode = ssl.CERT_NONE
            # NB: Set an upper-bound run time with timeout to prevent process hangs on network issues, otherwise
            # clients can hang indefinitely in certain network conditions:
            # NB: Mark urlopen() call with 'nosec' to acknowledge handling file:/ condition:
            LOGGER.debug("Calling urlopen(...)")
            response = urlopen(
                req,
                context=context,
                timeout=__MAX_RUN_TIME_IN_SECONDS
            )  # nosec
            LOGGER.debug("Finished urlopen(...)")
            global __JEBENA_TRACE_ID_OF_LAST_RUN_QUERY
            # HTTPMessage.__getitem__ returns None for a header the server didn't send,
            # so no guard is needed here:
            __JEBENA_TRACE_ID_OF_LAST_RUN_QUERY = response.info()["X-Log-Trace-ID"]
            LOGGER.debug("Jebena Trace ID: %s", __JEBENA_TRACE_ID_OF_LAST_RUN_QUERY)
            try:
                response_string = response.read().decode("utf-8")
            except Exception as exc:
                raise JebenaCliException(
                    "Invalid response from %s (%s; Jebena Trace ID: %s)" % (
                        api_endpoint,
                        exc,
                        __JEBENA_TRACE_ID_OF_LAST_RUN_QUERY
                    )
                )
            try:
                return json.loads(response_string)
            except JSONDecodeError:
                LOGGER.debug("Unable to decode response string:\n%s", response_string)
                raise JebenaCliGQLException(
                    "Invalid GQL response from %s (unable to parse '%s...'; Jebena Trace ID: %s)" %
                    (api_endpoint,
                     response_string[0:128],
                     __JEBENA_TRACE_ID_OF_LAST_RUN_QUERY
                     ),
                )

        except socket.timeout:
            run_time = int(time.time() - start_time)
            _log_and_raise_or_retry(
                "Socket Timeout error after %s seconds; max allowed is %s. (Hint: set ENV JEBENA_CLIENT_TIMEOUT)",
                run_time,
                __MAX_RUN_TIME_IN_SECONDS
            )
            continue

        except HTTPError as exc:  # noqa
            if exc.code == 401:
                # Regardless of retries left, always raise when using an unauthorized key:
                time.sleep(1)  # Delay a little on 401; in case we are called inside a loop
                _log_and_raise(
                    "Invalid or disabled Jebena API Key (HTTP 401 Unauthorized) "
                    "when using key %s on Jebena API Server %s",
                    api_key_name,
                    api_endpoint,
                )

            if exc.code == 429:
                _log_and_raise_or_retry(
                    "Jebena API Server %s has rate-limited the request.",
                    api_endpoint
                )
                retry_delay_next_attempt_extra_delay = 10
                continue

            # The response document may be a Jebena API Server error document, like so:
            #    {
            #      "details": {"errorType":"http",
            #                  "message":"Api-key not found.",
            #                  "status":401},
            #      "message":"Api-key not found.",
            #      "status":401
            #    }
            # The server's own message is already in there, so we surface the body
            # verbatim below rather than re-formatting it.
            response_body = "(Non-UTF-8 response)"
            try:
                response_body = exc.read().decode("utf-8", "replace")
            except (OSError, HTTPException):
                # Body could not be read off the socket; the status code will have to do.
                pass
            response_snippet = response_body[0:512]
            if len(response_body) > 512:
                response_snippet += "..."

            if exc.code in [502, 503]:
                _log_and_raise_or_retry(
                    "Jebena API Server %s returned an HTTP %s response\n"
                    "*** Server Response:\n%s",
                    api_endpoint,
                    exc.code,
                    response_snippet
                )
                continue

            # For now, we're just printing out the first KB of the raw JSON response.
            _log_and_raise(
                "Unknown Error; the Jebena API Server at %s has returned "
                "an unknown error (HTTP code: %s)\nResponse body:\n%s\n"
                "If this client should handle this error more gracefully, please file a bug at "
                "https://github.com/jebena/jebena-python-client/issues",
                api_endpoint,
                exc.code,
                response_snippet
            )

        except URLError as exc:  # noqa
            if attempts_allowed == 1 and _is_connection_refused(exc):
                # "Connection refused" means the TCP connection was never established,
                # so the server provably never saw this request. That makes a re-send
                # safe even for a mutation: there is nothing on the server to duplicate.
                # (Every other failure mode here is ambiguous -- a timeout or a dropped
                # connection may well have left a mutation applied server-side -- which
                # is why mutations otherwise get a single attempt.)
                attempts_allowed = 1 + retries_allowed
            _log_and_raise_or_retry(
                "URL Error (%s); check that the network is accessible and that "
                "the hostname is correct in Jebena API Server endpoint '%s'",
                str(exc),
                api_endpoint
            )
            continue

        except RemoteDisconnected as exc:
            _log_and_raise_or_retry(
                "Remote Disconnected Exception (%s)",
                str(exc)
            )
            continue

    # We shouldn't actually ever hit this condition, based on our above try/catch code,
    # but any programming error above could lead to falling off of the edge:
    raise JebenaCliException(
        "Unknown client issue when connecting to Jebena API Server at %s" % api_endpoint
    )


def read_query_and_return_response() -> str:
    """Read a query from STDIN (prompting if necessary) and return the server's response."""
    try:
        gql_query = read_from_stdin(
            user_prompt="Enter your GQL query, followed by return and "
                        "either Ctrl-D or . and another return.\n"
                        "For API documentation, point a web browser at your API endpoint.\n"
                        "Example query:  query { me { person { displayName } } }\n"
            )
        gql_variables = None
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        sys.exit(2)

    # Run and print response:
    gql_response = run_query(gql_query, variables=gql_variables)
    return json.dumps(gql_response, indent=2, sort_keys=True)


def read_from_stdin(user_prompt: Optional[str] = None) -> str:
    """Read from stdin until Ctrl-D, "." on empty line, or EOF occurs."""
    # If in a terminal, print some opening help:
    if sys.stdin.isatty() and user_prompt is not None:
        for line in user_prompt.split("\n"):
            print("\033[37m" + line + "\033[0m", file=sys.stderr)
    reads = []
    needs_newline_at_close = False
    while True:
        if sys.stdin.isatty():
            needs_newline_at_close = True
            this_read = sys.stdin.readline(4096)  # noqa: F841
            if this_read.rstrip() == ".":
                needs_newline_at_close = False
                break
        else:
            this_read = sys.stdin.read(4096)  # noqa: F841
        if this_read:
            reads.append(this_read)
        elif this_read is None:
            pass
        else:
            # EOF in non-tty; or Ctrl-D or empty-"."-line in terminal mode:
            break
    if needs_newline_at_close:
        # Annoying edge-case where in interactive mode, Ctrl-D doesn't put
        # the cursor a line-down, and the response doc prints on top of the "D".
        print("")
    return "".join(reads)


def __exit_client() -> NoReturn:
    """Terminates python with non-zero exit code when we're run as a command-line."""
    print(
        "Error: Request terminated. Jebena client exceeded max run time (%s seconds). "
        "This typically means the API server was unable to generate a response within a reasonable time. "
        "Check that the GQL query isn't over-fetching. It's also possible that more involved API calls may "
        "take longer than expected, in which case try temporarily increasing the timeout by setting the "
        "ENV variable 'JEBENA_CLIENT_TIMEOUT' in your shell: export JEBENA_CLIENT_TIMEOUT=%s"
        % (__MAX_RUN_TIME_IN_SECONDS, __MAX_RUN_TIME_IN_SECONDS * 2),
        file=sys.stderr
    )
    os._exit(3)  # noqa


def main() -> None:
    """
    Read a single query from STDIN, execute it, and print the server response to STDOUT.

    We place the main function here so that users can use this single .py file directly.
    """
    # Run read_query_and_return_response() with a watcher thread to terminate too-slow runs.
    watcher = Timer(__MAX_RUN_TIME_IN_SECONDS, __exit_client)
    try:
        # We limit runtime to prevent hangs on failed network connection or bad GQL queries:
        watcher.start()
        print(read_query_and_return_response())
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        sys.exit(99)
    except JebenaCliMissingKeyException:
        print(
            "Jebena API Keys missing; "
            "see https://github.com/jebena/jebena-python-client/blob/main/README.md",
            file=sys.stderr
        )
        sys.exit(99)
    except JebenaCliGQLException as exc:
        print("Jebena GQL Query Exception: %s" % exc, file=sys.stderr)
        sys.exit(1)
    except JebenaCliException as exc:
        print("Jebena GQL Client Error: %s" % exc, file=sys.stderr)
        sys.exit(2)
    finally:
        watcher.cancel()


if __name__ == "__main__":
    main()
