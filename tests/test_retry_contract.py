"""Tests for the mutation retry contract and the query/mutation scanner.

The contract under test: a request that may have reached the server must not be
re-sent when it could have written data. Everything here runs against a scripted
stand-in for urlopen, so no network and no live server is needed.
"""

import errno
import io
import json
import socket
import unittest
from http.client import RemoteDisconnected
from unittest import mock
from urllib.error import HTTPError, URLError

import jebenaclient.jebenaclient as jebenaclient

GQL_SUCCESS_PAYLOAD = b'{"data": {"ok": true}}'


def refused_connection():
    """Return the URLError that urlopen raises when the peer RSTs our SYN."""
    return URLError(ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"))


def dns_failure():
    """Return the URLError raised when the hostname does not resolve."""
    return URLError(socket.gaierror(-2, "Name or service not known"))


def http_error(code, body=b'{"message": "server said no"}'):
    """Return an HTTPError with a readable body, as urllib would raise."""
    return HTTPError("http://example.test/gql/", code, "Error", {}, io.BytesIO(body))


class FakeResponse:
    """Minimal stand-in for the object urlopen returns on success."""

    def __init__(self, payload=GQL_SUCCESS_PAYLOAD, trace_id="trace-test-1"):
        self._payload = payload
        self._trace_id = trace_id

    def info(self):
        return {"X-Log-Trace-ID": self._trace_id}

    def read(self):
        return self._payload


class ScriptedUrlopen:
    """Replay a fixed sequence of outcomes, counting how many sends were made."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.scripted = list(outcomes)
        self.requests = []
        self.calls = 0

    @property
    def payloads(self):
        """Return each sent request body, decoded from JSON."""
        return [json.loads(request.data.decode("utf-8")) for request in self.requests]

    def close(self):
        """Close every scripted HTTPError, used or not, to keep test output quiet."""
        for outcome in self.scripted:
            if hasattr(outcome, "close"):
                outcome.close()

    def __call__(self, request=None, *args, **kwargs):
        self.calls += 1
        self.requests.append(request)
        if not self.outcomes:
            raise AssertionError(
                "urlopen was called %s times; the test only scripted fewer outcomes"
                % self.calls
            )
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class ScriptedSendMixin:
    """Provides send(), which drives _execute_gql_query against a scripted urlopen."""

    MUTATION = "mutation { doThing }"
    QUERY = "query { me }"

    def send(self, query, *outcomes, **kwargs):
        """Run one query against a scripted urlopen; return (send_count, result)."""
        scripted = ScriptedUrlopen(*outcomes)
        self.scripted = scripted
        with mock.patch.object(jebenaclient, "urlopen", scripted), \
                mock.patch.object(jebenaclient.time, "sleep"):
            try:
                result = jebenaclient._execute_gql_query(
                    "http://example.test/",
                    query,
                    api_key_name="key-name",
                    api_secret_key="secret-key",
                    skip_logging_transient_errors=True,
                    **kwargs
                )
            except jebenaclient.JebenaCliException as exc:
                result = exc
            finally:
                scripted.close()
        return scripted.calls, result


class RetryContractTestCase(ScriptedSendMixin, unittest.TestCase):
    """Exercise _execute_gql_query's retry decisions."""

    # -- Ambiguous failures must never be retried for a mutation ---------------

    def test_mutation_is_not_retried_after_http_503(self):
        sends, _ = self.send(self.MUTATION, http_error(503), http_error(503))
        self.assertEqual(sends, 1)

    def test_mutation_is_not_retried_after_socket_timeout(self):
        sends, _ = self.send(self.MUTATION, socket.timeout(), socket.timeout())
        self.assertEqual(sends, 1)

    def test_mutation_is_not_retried_after_remote_disconnect(self):
        sends, _ = self.send(
            self.MUTATION, RemoteDisconnected("closed"), RemoteDisconnected("closed")
        )
        self.assertEqual(sends, 1)

    def test_mutation_is_not_retried_after_dns_failure(self):
        # A URLError that is not ECONNREFUSED proves nothing about whether the
        # request landed, so it must not buy a retry.
        sends, _ = self.send(self.MUTATION, dns_failure(), dns_failure())
        self.assertEqual(sends, 1)

    # -- A provably pre-send failure earns a retry ----------------------------

    def test_mutation_is_retried_when_connection_refused(self):
        sends, _ = self.send(
            self.MUTATION, refused_connection(), refused_connection(), refused_connection()
        )
        self.assertEqual(sends, 3)

    def test_mutation_succeeds_on_retry_after_refused_connection(self):
        sends, result = self.send(self.MUTATION, refused_connection(), FakeResponse())
        self.assertEqual(sends, 2)
        self.assertEqual(result, {"data": {"ok": True}})

    # -- The regression this contract exists for ------------------------------

    def test_refused_connection_does_not_license_a_later_ambiguous_retry(self):
        """A refused attempt must not widen the budget for a later ambiguous failure.

        Attempt 1 is refused, so it provably did not write and a retry is safe.
        Attempt 2 reaches the server and comes back 503 -- the mutation may well
        have applied. There must be no attempt 3.
        """
        sends, _ = self.send(
            self.MUTATION, refused_connection(), http_error(503), FakeResponse()
        )
        self.assertEqual(sends, 2)

    def test_comment_prefixed_mutation_is_not_retried(self):
        """A leading GQL comment must not disguise a mutation as a retryable query."""
        sends, _ = self.send(
            "# Create the record\nmutation CreateThing { x }",
            http_error(503),
            http_error(503),
            FakeResponse()
        )
        self.assertEqual(sends, 1)

    def test_named_mutation_is_not_retried(self):
        sends, _ = self.send(
            "mutation UpdateUser { x }", http_error(503), http_error(503), FakeResponse()
        )
        self.assertEqual(sends, 1)

    def test_bom_prefixed_mutation_is_not_retried(self):
        sends, _ = self.send(
            "\ufeffmutation CreateThing { x }", http_error(503), FakeResponse()
        )
        self.assertEqual(sends, 1)

    def test_refused_then_timeout_does_not_retry(self):
        sends, _ = self.send(
            self.MUTATION, refused_connection(), socket.timeout(), FakeResponse()
        )
        self.assertEqual(sends, 2)

    # -- Reads keep their full retry budget -----------------------------------

    def test_query_is_retried_after_ambiguous_failure(self):
        sends, result = self.send(
            self.QUERY, http_error(503), http_error(503), FakeResponse()
        )
        self.assertEqual(sends, 3)
        self.assertEqual(result, {"data": {"ok": True}})

    def test_query_retry_budget_is_bounded(self):
        sends, _ = self.send(
            self.QUERY, http_error(503), http_error(503), http_error(503)
        )
        self.assertEqual(sends, 3)

    def test_allow_retries_on_mutations_restores_the_full_budget(self):
        sends, result = self.send(
            self.MUTATION,
            http_error(503),
            http_error(503),
            FakeResponse(),
            allow_retries_on_mutations=True
        )
        self.assertEqual(sends, 3)
        self.assertEqual(result, {"data": {"ok": True}})

    def test_http_401_never_retries(self):
        sends, _ = self.send(self.QUERY, http_error(401), FakeResponse())
        self.assertEqual(sends, 1)


class QueryScannerTestCase(unittest.TestCase):
    """Exercise _is_query_retry_safe, which must fail closed."""

    def assert_retry_safe(self, query):
        self.assertTrue(
            jebenaclient._is_query_retry_safe(query),
            "expected retry-safe: %r" % query
        )

    def assert_not_retry_safe(self, query):
        self.assertFalse(
            jebenaclient._is_query_retry_safe(query),
            "expected NOT retry-safe: %r" % query
        )

    def test_plain_queries_are_retry_safe(self):
        self.assert_retry_safe("query { me }")
        self.assert_retry_safe("  \n\t query getName { me }")
        self.assert_retry_safe("query($a: String) { me }")
        self.assert_retry_safe("query{me}")

    def test_anonymous_shorthand_query_is_retry_safe(self):
        self.assert_retry_safe("{ me { person { displayName } } }")
        self.assert_retry_safe("\n  { me }")

    def test_queries_behind_ignored_tokens_are_retry_safe(self):
        self.assert_retry_safe("# fetch my name\nquery { me }")
        self.assert_retry_safe("﻿query { me }")
        self.assert_retry_safe(",,, query { me }")
        self.assert_retry_safe("# one\n# two\n\n  query { me }")

    def test_plain_mutations_are_not_retry_safe(self):
        self.assert_not_retry_safe("mutation { doThing }")
        self.assert_not_retry_safe("mutation{doThing}")
        self.assert_not_retry_safe("MUTATION { doThing }")
        self.assert_not_retry_safe("  \n mutation($a: String) { doThing }")

    def test_named_mutations_are_not_retry_safe(self):
        self.assert_not_retry_safe("mutation UpdateUser { x }")
        self.assert_not_retry_safe("mutation UpdateUser($id: ID!) { x }")
        self.assert_not_retry_safe("mutation {}")
        self.assert_not_retry_safe("mutation{}")

    def test_mutations_behind_ignored_tokens_are_not_retry_safe(self):
        # A leading comment or BOM must not disguise a mutation as a query:
        self.assert_not_retry_safe("# Create the record\nmutation CreateThing { x }")
        self.assert_not_retry_safe("﻿mutation CreateThing { x }")
        self.assert_not_retry_safe(", mutation CreateThing { x }")
        self.assert_not_retry_safe("#c1\n#c2\nmutation CreateThing { x }")

    def test_comment_only_document_is_not_retry_safe(self):
        self.assert_not_retry_safe("# nothing but a comment")
        self.assert_not_retry_safe("")

    def test_fragment_first_documents_are_not_retry_safe(self):
        # Valid GQL: a fragment definition may precede the operation. We cannot tell
        # what follows without a real parser, so we fail closed.
        self.assert_not_retry_safe("fragment F on T { x }\nmutation M { doThing { ...F } }")
        self.assert_not_retry_safe("fragment F on T { x }\nquery Q { me { ...F } }")

    def test_wrapped_json_is_not_retry_safe(self):
        # A wrapped query also starts with "{" and may wrap a mutation. run_query()
        # normally unwraps it first, but it must not be mistaken for a shorthand query.
        self.assert_not_retry_safe('{"query": "mutation { doThing }"}')
        self.assert_not_retry_safe('{ "query": "mutation { doThing }" }')

    def test_lookalike_operation_names_are_classified_by_operation_type(self):
        self.assert_retry_safe("query mutationsById { x }")
        self.assert_not_retry_safe("mutationLike { x }")
        self.assert_not_retry_safe("queryFoo { x }")


class RequestPayloadTestCase(ScriptedSendMixin, unittest.TestCase):
    """Exercise how the outbound GQL request body is serialized."""

    def sent_payload(self, **kwargs):
        """Send one successful query and return the request body that went out."""
        self.send(self.QUERY, FakeResponse(), **kwargs)
        return self.scripted.payloads[0]

    def test_absent_variables_serialize_as_an_empty_map(self):
        # GQL defines "variables" as a map; an empty list is invalid per spec.
        self.assertEqual(self.sent_payload()["variables"], {})

    def test_explicit_variables_are_preserved(self):
        payload = self.sent_payload(variables={"someUUID": "abc", "count": 2})
        self.assertEqual(payload["variables"], {"someUUID": "abc", "count": 2})

    def test_explicitly_empty_variables_are_left_alone(self):
        self.assertEqual(self.sent_payload(variables={})["variables"], {})

    def test_falsy_variable_values_survive(self):
        # A dict of falsy values is still a real variable map and must not be dropped.
        payload = self.sent_payload(variables={"flag": False, "count": 0, "name": ""})
        self.assertEqual(payload["variables"], {"flag": False, "count": 0, "name": ""})

    def test_operation_name_is_sent_only_when_given(self):
        self.assertNotIn("operationName", self.sent_payload())
        self.assertEqual(
            self.sent_payload(operation_name="getName")["operationName"], "getName"
        )

    def test_query_is_sent_verbatim(self):
        self.assertEqual(self.sent_payload()["query"], self.QUERY)


class ConnectionRefusedDetectionTestCase(unittest.TestCase):
    """Exercise _is_connection_refused."""

    def test_detects_econnrefused(self):
        self.assertTrue(jebenaclient._is_connection_refused(refused_connection()))

    def test_ignores_dns_failures(self):
        # gaierror carries EAI_* codes in .errno, which overlap the errno space.
        self.assertFalse(jebenaclient._is_connection_refused(dns_failure()))

    def test_ignores_other_socket_errors(self):
        self.assertFalse(jebenaclient._is_connection_refused(
            URLError(ConnectionResetError(errno.ECONNRESET, "Connection reset"))
        ))

    def test_ignores_a_reasonless_error(self):
        self.assertFalse(jebenaclient._is_connection_refused(URLError("no reason")))


if __name__ == "__main__":
    unittest.main()
