"""Tests for the mutation retry contract and the query/mutation scanner.

The contract under test: a request that may have reached the server must not be
re-sent when it could have written data. Everything here runs against a scripted
stand-in for urlopen, so no network and no live server is needed.
"""

import datetime
import email.utils
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


def http_error(code, body=b'{"message": "server said no"}', retry_after=None):
    """Return an HTTPError with a readable body, as urllib would raise."""
    headers = {} if retry_after is None else {"Retry-After": retry_after}
    return HTTPError("http://example.test/gql/", code, "Error", headers, io.BytesIO(body))


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
                mock.patch.object(jebenaclient.time, "sleep") as sleep_mock:
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
        self.sleeps = [call.args[0] for call in sleep_mock.call_args_list]
        return scripted.calls, result


class RetryContractTestCase(ScriptedSendMixin, unittest.TestCase):
    """Exercise _execute_gql_query's retry decisions."""

    AMBIGUOUS = [
        ("http 503", http_error(503)),
        ("socket timeout", socket.timeout()),
        ("remote disconnect", RemoteDisconnected("closed")),
        ("dns failure", dns_failure()),          # a URLError that is not ECONNREFUSED
    ]

    def test_a_mutation_is_never_retried_after_an_ambiguous_failure(self):
        for label, failure in self.AMBIGUOUS:
            with self.subTest(failure=label):
                sends, _ = self.send(self.MUTATION, failure, FakeResponse())
                self.assertEqual(sends, 1)

    def test_a_mutation_is_retried_when_the_connection_was_refused(self):
        sends, result = self.send(self.MUTATION, refused_connection(), FakeResponse())
        self.assertEqual(sends, 2)
        self.assertEqual(result, {"data": {"ok": True}})

    def test_a_refused_connection_does_not_license_a_later_ambiguous_retry(self):
        """The regression this contract exists for: the second failure is ambiguous."""
        for label, failure in (("503", http_error(503)), ("timeout", socket.timeout())):
            with self.subTest(second_failure=label):
                sends, _ = self.send(
                    self.MUTATION, refused_connection(), failure, FakeResponse())
                self.assertEqual(sends, 2)

    def test_a_mutation_behind_a_leading_comment_is_still_a_mutation(self):
        sends, _ = self.send(
            "# Create the record\nmutation CreateThing { x }", http_error(503), FakeResponse())
        self.assertEqual(sends, 1)

    def test_a_query_keeps_its_full_retry_budget(self):
        sends, result = self.send(self.QUERY, http_error(503), http_error(503), FakeResponse())
        self.assertEqual(sends, 3)
        self.assertEqual(result, {"data": {"ok": True}})

    def test_allow_retries_on_mutations_restores_the_full_budget(self):
        sends, _ = self.send(
            self.MUTATION, http_error(503), http_error(503), FakeResponse(),
            allow_retries_on_mutations=True)
        self.assertEqual(sends, 3)

    def test_http_401_never_retries(self):
        sends, _ = self.send(self.QUERY, http_error(401), FakeResponse())
        self.assertEqual(sends, 1)


class QueryScannerTestCase(unittest.TestCase):
    """_is_query_retry_safe must fail closed: only a recognizable query is retry-safe."""

    DOCUMENTS = [
        # retry-safe reads
        ("query { me }", True),
        ("  \n\t query getName { me }", True),
        ("query($a: String) { me }", True),
        ("query{me}", True),
        ("{ me { person { displayName } } }", True),
        ("# fetch my name\nquery { me }", True),
        ("\ufeffquery { me }", True),
        (",,, query { me }", True),
        ("query mutationsById { x }", True),
        ('query S { search(term: "mutation") { id } }', True),      # string contents
        ('query D { doc(body: """a mutation""") { id } }', True),   # block string
        ("query S {\n # mutation examples\n s(t: 1) { id } }", True),
        # not retry-safe
        ("mutation { doThing }", False),
        ("mutation{doThing}", False),
        ("MUTATION { doThing }", False),
        ("mutation UpdateUser($id: ID!) { x }", False),
        ("# Create the record\nmutation CreateThing { x }", False),
        ("\ufeffmutation CreateThing { x }", False),
        ("query A { me }\nmutation B { charge }", False),          # operation_name may pick B
        ('query S { search(term: "unterminated mutation) { id } }', False),
        ("fragment F on T { x }\nquery Q { me { ...F } }", False),  # cannot scan past a fragment
        ('{"query": "mutation { doThing }"}', False),               # wrapped JSON, not shorthand
        ("mutationLike { x }", False),
        ("queryFoo { x }", False),
        ("# nothing but a comment", False),
        ("", False),
    ]

    def test_classification(self):
        for document, expected in self.DOCUMENTS:
            with self.subTest(document=document):
                self.assertEqual(jebenaclient._is_query_retry_safe(document), expected)


class RequestPayloadTestCase(ScriptedSendMixin, unittest.TestCase):
    """GQL defines "variables" as a map; an empty list is invalid and once shipped."""

    def test_variables_and_operation_name_serialize_correctly(self):
        self.send(self.QUERY, FakeResponse())
        self.assertEqual(self.scripted.payloads[0], {"query": self.QUERY, "variables": {}})
        self.send(self.QUERY, FakeResponse(), variables={"flag": False}, operation_name="n")
        self.assertEqual(
            self.scripted.payloads[0],
            {"query": self.QUERY, "variables": {"flag": False}, "operationName": "n"})


class RetryAfterHeaderTestCase(ScriptedSendMixin, unittest.TestCase):
    """Retry-After (plus a second) sets the delay; our own schedule is the fallback."""

    DELAYS = [
        # status, Retry-After, expected sleeps, why
        (503, "30", [31], "longer than our own delay"),
        (503, "5", [6], "shorter than our own delay -- still honored"),
        (503, "0", [1], "zero still waits the added second"),
        (503, "8.4", [10], "fractional value is rounded up, then padded"),
        (503, None, [2], "no header -- our own first delay"),
        (429, "8", [9], "throttle delay honored"),
        (429, None, [2], "no header -- our own first delay"),
    ]

    def test_delay_comes_from_the_header_when_present(self):
        for status, header, expected, why in self.DELAYS:
            with self.subTest(status=status, retry_after=header, why=why):
                self.send(self.QUERY, http_error(status, retry_after=header), FakeResponse())
                self.assertEqual(self.sleeps, expected)

    def test_http_date_is_honored(self):
        soon = email.utils.format_datetime(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=60))
        self.send(self.QUERY, http_error(503, retry_after=soon), FakeResponse())
        self.assertEqual(len(self.sleeps), 1)
        self.assertTrue(60 <= self.sleeps[0] <= 62, self.sleeps)

    def test_header_applies_per_failure_and_is_not_sticky(self):
        self.send(self.QUERY, http_error(503, retry_after="30"), http_error(503), FakeResponse())
        self.assertEqual(self.sleeps, [31, 10])

    def test_backstop_reserves_room_for_the_retry_itself(self):
        # The 201s sleep fits inside the 400s backstop, but the attempt after it would not.
        with mock.patch.object(jebenaclient, "__MAX_TOTAL_RUN_TIME_IN_SECONDS", 400), \
                mock.patch.object(jebenaclient, "__REQUEST_TIMEOUT_IN_SECONDS", 300):
            sends, _ = self.send(self.QUERY, http_error(503, retry_after="200"), FakeResponse())
        self.assertEqual((sends, self.sleeps), (1, []))

    def test_delay_past_the_run_backstop_gives_up_instead_of_sleeping(self):
        with mock.patch.object(jebenaclient, "__MAX_TOTAL_RUN_TIME_IN_SECONDS", 20):
            sends, result = self.send(self.QUERY, http_error(503, retry_after="600"), FakeResponse())
        self.assertEqual((sends, self.sleeps), (1, []))
        self.assertIn("waiting 601 seconds", str(result))


class RateLimitRetryTestCase(ScriptedSendMixin, unittest.TestCase):
    """429 is synthesised before GraphQL runs, so re-sending is safe."""

    def test_429_is_retried_for_query_and_mutation(self):
        for query in (self.QUERY, self.MUTATION):
            with self.subTest(query=query):
                sends, result = self.send(query, http_error(429), FakeResponse())
                self.assertEqual(sends, 2)
                self.assertEqual(result, {"data": {"ok": True}})

    def test_mutation_still_refuses_an_ambiguous_503_after_a_429(self):
        sends, _ = self.send(self.MUTATION, http_error(429), http_error(503), FakeResponse())
        self.assertEqual(sends, 2)

    def test_a_selected_mutation_in_a_multi_operation_document_is_not_retried(self):
        """operation_name picks which operation runs, so a mutation anywhere is unsafe."""
        document = ("query ReadOnly { me { person { displayName } } }\n"
                    "mutation ChargeCard { chargeCard { id } }")
        self.assertFalse(jebenaclient._is_query_retry_safe(document))
        sends, _ = self.send(document, http_error(503), FakeResponse(),
                             operation_name="ChargeCard")
        self.assertEqual(sends, 1)

    def test_mutation_retry_is_gated_on_the_named_assumption(self):
        """Emptying the tuple must stop the retry, or JEBENA_SERVER_ASSUMPTION is decorative."""
        with mock.patch.object(
                jebenaclient, "__HTTP_STATUS_CODES_REJECTED_BEFORE_EXECUTION", ()):
            sends, _ = self.send(self.MUTATION, http_error(429), FakeResponse())
        self.assertEqual(sends, 1)


VARNISH_SYNTH_HTML = b"<html><body><h3>API Server Error (405)</h3></body></html>"


class SynthStatusTestCase(ScriptedSendMixin, unittest.TestCase):
    """Varnish synths 400/405/418 with an HTML body and no Retry-After."""

    def test_they_never_retry_never_sleep_and_surface_the_body(self):
        for code in (400, 405, 418):
            for query in (self.QUERY, self.MUTATION):
                with self.subTest(code=code, query=query):
                    sends, result = self.send(query, http_error(code, VARNISH_SYNTH_HTML))
                    self.assertEqual((sends, self.sleeps), (1, []))
                    self.assertIn("API Server Error", str(result))

    def test_non_utf8_body_still_raises_cleanly(self):
        _, result = self.send(self.QUERY, http_error(400, b"\xff\xfe not utf-8"))
        self.assertIsInstance(result, jebenaclient.JebenaCliException)


class RetryAfterParsingTestCase(unittest.TestCase):
    """Exercise _get_retry_after_in_seconds."""

    VALUES = [
        ("30", 30), ("0", 0), (" 15 ", 15),
        ("1.5", 2), ("8.4", 9),          # fractional values round up
        (None, None), ("", None), ("soon", None), ("-10", None),
        ("inf", None), ("nan", None), ("1e400", None),   # float() takes these; ceil cannot
        ("Mon, 99 Xxx 2026 07:28:00 GMT", None),         # malformed date
    ]

    @staticmethod
    def parse(raw):
        exc = http_error(503, retry_after=raw)
        try:
            return jebenaclient._get_retry_after_in_seconds(exc)
        finally:
            exc.close()

    def test_http_date_is_measured_against_now(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        soon = self.parse(email.utils.format_datetime(now + datetime.timedelta(seconds=60)))
        self.assertTrue(60 <= soon <= 61, soon)
        # A date already past means "go now"; fall back to our own delay rather than 0.
        self.assertIsNone(
            self.parse(email.utils.format_datetime(now - datetime.timedelta(seconds=60))))

    def test_whole_and_fractional_seconds_are_honored(self):
        for raw, expected in self.VALUES:
            with self.subTest(retry_after=raw):
                exc = http_error(503, retry_after=raw)
                try:
                    self.assertEqual(jebenaclient._get_retry_after_in_seconds(exc), expected)
                finally:
                    exc.close()

    def test_error_without_headers(self):
        self.assertIsNone(jebenaclient._get_retry_after_in_seconds(URLError("no headers")))


class TraceIdTestCase(ScriptedSendMixin, unittest.TestCase):
    """get_last_run_trace_id() must describe the call that just ran, not an older one."""

    def test_a_failed_call_does_not_leave_the_previous_trace_id(self):
        self.send(self.QUERY, FakeResponse(trace_id="trace-1"))
        self.assertEqual(jebenaclient.get_last_run_trace_id(), "trace-1")
        # A query retries, so script a refusal for every attempt:
        self.send(self.QUERY, *[refused_connection()] * 3)
        self.assertIsNone(jebenaclient.get_last_run_trace_id())

    def test_an_http_error_without_headers_does_not_crash(self):
        exc = http_error(500)
        exc.headers = None
        _, result = self.send(self.QUERY, exc)
        self.assertIsInstance(result, jebenaclient.JebenaCliException)
        self.assertIsNone(jebenaclient.get_last_run_trace_id())

    def test_validation_failures_in_run_query_also_clear_the_trace(self):
        self.send(self.QUERY, FakeResponse(trace_id="trace-1"))
        self.assertEqual(jebenaclient.get_last_run_trace_id(), "trace-1")
        with self.assertRaises(jebenaclient.JebenaCliGQLException):
            jebenaclient.run_query("")          # rejected before any request is built
        self.assertIsNone(jebenaclient.get_last_run_trace_id())

    def test_trace_id_is_taken_from_an_http_error_too(self):
        exc = http_error(500)
        exc.headers = {"X-Log-Trace-ID": "trace-from-error"}
        self.send(self.QUERY, exc)
        self.assertEqual(jebenaclient.get_last_run_trace_id(), "trace-from-error")


class RunTimeBudgetTestCase(unittest.TestCase):
    """The per-request timeout must not double as the total run backstop.

    Until 0.12.0 it was both, so the first attempt spent the whole allowance and the
    `except socket.timeout` retry could never fire.
    """

    TIMEOUT = 3

    def attempts_under_backstop(self, backstop):
        """Count sends when every attempt times out, against an honest wall clock."""
        clock = [1000.0]
        scripted = ScriptedUrlopen(*[socket.timeout()] * 3)

        def tick(seconds):
            clock[0] += seconds

        def urlopen(*args, **kwargs):
            tick(self.TIMEOUT)          # the socket really did wait
            return scripted(*args, **kwargs)

        with mock.patch.object(jebenaclient, "__REQUEST_TIMEOUT_IN_SECONDS", self.TIMEOUT), \
                mock.patch.object(jebenaclient, "__MAX_TOTAL_RUN_TIME_IN_SECONDS", backstop), \
                mock.patch.object(jebenaclient, "urlopen", urlopen), \
                mock.patch.object(jebenaclient.time, "sleep", tick), \
                mock.patch.object(jebenaclient.time, "monotonic", lambda: clock[0]):
            with self.assertRaises(jebenaclient.JebenaCliException):
                jebenaclient._execute_gql_query(
                    "http://example.test/", "query { me }", api_key_name="key-name",
                    api_secret_key="secret-key", skip_logging_transient_errors=True)
        return scripted.calls

    def test_timeouts_retry_under_a_derived_backstop_but_not_an_equal_one(self):
        self.assertGreater(
            getattr(jebenaclient, "__MAX_TOTAL_RUN_TIME_IN_SECONDS"),
            getattr(jebenaclient, "__REQUEST_TIMEOUT_IN_SECONDS")
        )
        self.assertEqual(self.attempts_under_backstop(3 * self.TIMEOUT + 100), 3)
        self.assertEqual(self.attempts_under_backstop(self.TIMEOUT), 1)
        # Discriminating case: only real elapsed-time accounting stops this at one send.
        self.assertEqual(self.attempts_under_backstop(7), 1)


class ConnectionRefusedDetectionTestCase(unittest.TestCase):
    """Only ECONNREFUSED proves the request never left."""

    ERRORS = [
        (refused_connection(), True),
        (dns_failure(), False),          # gaierror puts EAI_* codes in the same .errno space
        (URLError(ConnectionResetError(errno.ECONNRESET, "Connection reset")), False),
        (URLError("no reason"), False),
    ]

    def test_detection(self):
        for exc, expected in self.ERRORS:
            with self.subTest(reason=repr(getattr(exc, "reason", None))):
                self.assertEqual(jebenaclient._is_connection_refused(exc), expected)
