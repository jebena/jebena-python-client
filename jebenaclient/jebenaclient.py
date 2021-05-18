#!/usr/bin/env python3  # noqa -- the hash-bang line here allows for direct script execution

# While we call for python3, we do need to support Python 2.7 for a bit longer:
from __future__ import print_function

"""
A very simply GQL Client for the Jebena API Server.

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

Example of a simply GQL query:
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
__version__ = "0.8.7"

import json
import logging
import os
import pprint
import socket
import ssl
import sys
import time
from threading import Timer

# Python 2 compatibility:
try:
    from http.client import RemoteDisconnected
except ImportError:
    from httplib import BadStatusLine as RemoteDisconnected  # Py 2
try:
    from json.decoder import JSONDecodeError as json_JSONDecodeError
except ImportError:
    # In Python 2, json.loads() raises this instead of JSONDecodeError:
    json_JSONDecodeError = ValueError  # Py 2
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse  # Py 2
try:
    import urllib.request as urllib_request
    from urllib.error import HTTPError as urllib_HTTPError
    from urllib.error import URLError as urllib_URLError
    from urllib.request import urlopen
except ImportError:
    import urllib2 as urllib_request  # Py 2
    from urllib2 import HTTPError as urllib_HTTPError
    from urllib2 import URLError as urllib_URLError
    from urllib2 import urlopen  # Py 2

LOGGER = logging.getLogger("jebenaclient")
if sys.version_info[0] == 2:
    logging.basicConfig()

class JebenaCliException(Exception):
    """Generic client error, indicating an issue with the connection or setup."""


class JebenaCliGQLException(JebenaCliException):
    """GQL-specific error, raised when the server response indicates a bad query."""


class JebenaCliMissingKeyException(JebenaCliException):
    """Raised when client credentials are missing or the user is invalid."""


class JebenaCliGQLPermissionDenied(JebenaCliException):
    """Raised when the user does not have sufficient server permissions for the query."""


def run_query(
        query,
        operation_name=None,
        variables=None,
        api_endpoint=None,
        api_key_name=None,
        api_secret_key=None,
        allow_insecure_https=False,
        allow_retries_on_mutations=False,
        return_instead_of_raise_on_errors=False,
        skip_logging_transient_errors=False
):
    # type: (str, str, dict, str, str, str, bool, bool, bool, bool) -> dict
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
    if not query:
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
        except Exception:  # noqa
            # For Python 2 compatibility: don't try to catch 'json.decoder.JSONDecodeError'
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


def _execute_gql_query(
        api_endpoint,
        query,
        operation_name=None,
        variables=None,
        allow_insecure_https=False,
        api_key_name=None,
        api_secret_key=None,
        retries_allowed=2,
        allow_retries_on_mutations=False,
        skip_logging_transient_errors=False
):
    # type: (str, str, str, dict, bool, str, str, int, bool) -> dict
    """Send a GQL query to the server and return the GQL response."""
    if not api_key_name:
        raise JebenaCliMissingKeyException(
            "Missing API Key Name (Try setting ENV variable JEBENA_API_KEY_NAME)"
        )
    if not api_secret_key:
        raise JebenaCliMissingKeyException(
            "Missing API Secret Key (Try setting ENV variable JEBENA_API_SECRET_KEY)"
        )
    if not variables:
        variables = []
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
    is_query_a_mutation = False
    if query.split(None, 2)[0].lower() == 'mutation':
        # NB: avoid split()'s kwargs for Python 2 compatibility.
        # In split() 'None' is separator of whitespace and 2 is maxsplit
        is_query_a_mutation = True
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
    req = urllib_request.Request(
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
    attempts_tried = 0
    retry_delay_constant_delay = 5
    retry_delay_next_attempt_extra_delay = 0
    retry_delay_factor = 3

    def _log_and_raise_or_retry(log_message, *args):
        # type: (str, str) -> None
        """Log error and either return if retries allowed or raise."""
        if attempts_tried < attempts_allowed:
            if not skip_logging_transient_errors:
                LOGGER.warning(log_message, *args)
            return
        _log_and_raise(log_message, *args)

    def _log_and_raise(log_message, *args):
        # type: (str, str) -> "NoReturn"  # noqa
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
                    "Failed to fetch from %s; retry in %s seconds; %s attempts left.",
                    api_endpoint,
                    retry_delay,
                    (attempts_allowed - attempts_tried + 1)  # We're after the += 1 above
                )
            time.sleep(retry_delay)

        try:
            context = None
            if allow_insecure_https:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)  # Pass ssl.PROTOCOL_TLS for Py 2.7 compatibility
            # Set an upper-bound to prevent process hangs on network issues, otherwise
            # clients can hang indefinitely in certain network conditions:
            connection_timeout_in_seconds = 300
            # NB: Mark urlopen() call with 'nosec' to acknowledge handling file:/ condition:
            LOGGER.debug("Calling urlopen(...)")
            response = urlopen(
                req,
                context=context,
                timeout=connection_timeout_in_seconds
            )  # nosec
            LOGGER.debug("Finished urlopen(...)")
            try:
                response_string = response.read().decode("utf-8")
            except Exception as exc:
                raise JebenaCliException(
                    "Invalid response from %s (%s)" % (api_endpoint, exc)
                )
            try:
                return json.loads(response_string)
            except json_JSONDecodeError:
                LOGGER.debug("Unable to decode response string:\n%s", response_string)
                raise JebenaCliGQLException(
                    "Invalid GQL response from %s (unable to parse JSON: '%s...')" %
                    (api_endpoint, response_string[0:128])
                )

        except socket.timeout:
            _log_and_raise_or_retry("Socket Timeout error")
            continue

        except urllib_HTTPError as exc:  # qa
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

            # Response document may be a Jebena API Server response with info:
            response = "(Non-UTF-8 response)"
            try:
                response = exc.read().decode("utf-8", "replace")
                # response can potentially be a JSON doc from Jebena API server, like so:
                #    {
                #      "details": {"errorType":"http",
                #                  "message":"Api-key not found.",
                #                  "status":401},
                #      "message":"Api-key not found.",
                #      "status":401
                #    }
                # Try parsing the response to see if we have an error that we can wrap and make
                # more understandable in the context of our client:
                response_data = json.loads(response)
                LOGGER.critical(
                    "Please file a bug report at "
                    "https://github.com/jebena/jebena-python-client/issues for this:\n"
                    "We should add handling for this error:\n%s", response_data
                )
            except BaseException:  # noqa
                # NB: for Py 2.7 support, we need to catch something that exists in that version.
                pass
            response_snippet = response[0:512]
            if len(response) > 512:
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
                "an unknown error (HTTP code: %s)\nResponse body:\n%s",
                api_endpoint,
                exc.code,
                response_snippet
            )

        except urllib_URLError as exc:  # noqa
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
        "Unknown client issue when connection to Jebena API Server at %s" % api_endpoint
    )


def read_query_and_return_response():
    # type: () -> str
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


def read_from_stdin(user_prompt=None):
    # type: (str) -> str
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


def __exit_client():
    """Terminates python with non-zero exit code when we're run as a command-line."""
    print("Client exceeded reasonable run time; terminating.", file=sys.stderr)
    os._exit(3)  # noqa


def main():
    """
    Read a single query from STDIN, execute it, and print the server response to STDOUT.

    We place the main function here so that users can use this single .py file directly.
    """
    # Our script uses both python's logger and print-to-stderr. We default to
    # python's logger for import cases and flip to a print-to-stderr mode when
    # used as in a command line mode.
    logging_format = "Jebena GQL Client %(levelname)s: %(message)s"
    logging.basicConfig(format=logging_format)
    LOGGER.setLevel(logging.WARNING)

    # Run read_query_and_return_response() with a watcher thread to terminate too-slow runs.
    maximum_run_time = 60 * 5
    watcher = Timer(maximum_run_time, __exit_client)
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
            "see https://github.com/jebena/jebena-python-client/blob/main/README.md"
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
