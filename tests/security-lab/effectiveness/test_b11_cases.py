"""Unit tests for the two WAF batch 11 cases (plan 4.5, batch 8). The gateway is not started: the requests are stubbed, so
the setup, its refusals and its error paths run without a network. The statuses are checked here; the gateway's answers
are checked by the lab run itself."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock
from urllib.parse import quote

from effectiveness import lab, probes, regressions


def _source(index: int, *, net: int = 1) -> str:
    return f"127.0.{net}.{index}"


def _reply(status: int) -> SimpleNamespace:
    return SimpleNamespace(reply=SimpleNamespace(status=status, request_id=None), served=True)


def _prober(jev: object | None = None) -> probes.Prober:
    site = probes.Site(name=lab.SITE_LIMIT, config="truth", mode="enforce", origin=None)
    return probes.Prober(None, site, probes.Pool(), jev=jev)


class _ModelCalls:
    """Stands in for the ideal model's record: `states` gets one entry for each call the model answers."""

    def __init__(self) -> None:
        self.states: list[str] = []


class ForgedSessionsCaseTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.object(regressions.labkit, "loopback_source", side_effect=_source)
        self.addCleanup(patcher.stop)
        patcher.start()

    @staticmethod
    def stub(p: probes.Prober, respond) -> list[tuple[probes.Session, str, dict]]:
        sent: list[tuple[probes.Session, str, dict]] = []

        def request(session, method, target, **options):
            sent.append((session, target, options))
            return respond(target, options)

        p.request = request
        return sent

    def test_the_setup_spends_twenty_calls_then_the_eleventh_injection_is_refused_at_the_limit(self):
        model = _ModelCalls()

        def respond(target, options):
            if options.get("scored"):
                return _reply(429)
            if "/api/search" in target:
                model.states.append(target)  # the model answers each new word once
                return _reply(401)
            return _reply(200)

        p = _prober(model)
        sent = self.stub(p, respond)
        regressions.forged_sessions_total_cap(p)

        logins = [session for session, target, _ in sent if target == "/login"]
        self.assertEqual(len(logins), regressions.FORGED_SESSIONS)
        self.assertEqual({session.source for session in logins}, {"127.0.2.1"})
        self.assertEqual(len({session.token for session in logins}), regressions.FORGED_SESSIONS)
        setup = [target for _, target, options in sent if "/api/search" in target and not options.get("scored")]
        self.assertEqual(len(setup), 2 * (regressions.FORGED_SESSIONS - 1))
        self.assertEqual(len(model.states), 2 * (regressions.FORGED_SESSIONS - 1))
        scored = [(target, options) for _, target, options in sent if options.get("scored")]
        self.assertEqual(len(scored), 1)
        attack = regressions._second_sqli()
        self.assertEqual(scored[0][0], f"/api/search?q={quote(attack, safe='')}")
        self.assertEqual(scored[0][1]["carry"], attack)

    def test_a_refused_setup_request_is_an_error_not_a_score(self):
        p = _prober()
        self.stub(p, lambda target, options: _reply(429 if "/api/search" in target else 200))
        with self.assertRaises(probes.ProbeError):
            regressions.forged_sessions_total_cap(p)

    def test_setup_that_spends_no_model_calls_is_an_error_when_the_model_is_observable(self):
        p = _prober(_ModelCalls())
        self.stub(p, lambda target, options: _reply(401 if "/api/search" in target else 200))
        with self.assertRaisesRegex(probes.ProbeError, "spent 0 model calls"):
            regressions.forged_sessions_total_cap(p)

    def test_in_a_live_run_the_setup_is_not_counted_here_and_the_scored_request_is_still_sent(self):
        p = _prober(None)
        sent = self.stub(p, lambda target, options: _reply(429 if options.get("scored") else 401))
        regressions.forged_sessions_total_cap(p)
        self.assertTrue(any(options.get("scored") for _, _, options in sent))

    def test_a_system_that_cannot_send_from_the_range_refuses_the_case_instead_of_sharing_an_address(self):
        with mock.patch.object(regressions.labkit, "loopback_source", return_value=None):
            with self.assertRaises(probes.ProbeError):
                regressions.forged_sessions_total_cap(_prober())


class OtherAddressCaseTests(unittest.TestCase):
    def test_a_real_doctor_on_the_other_address_asks_one_new_word_and_is_scored_as_allowed(self):
        p = _prober()
        logins: list[tuple[str, str | None]] = []
        sent: list[tuple[str, dict]] = []

        def login(account, *, source=None):
            logins.append((account, source))
            return probes.Session(source=source, token="real")

        def request(session, method, target, **options):
            sent.append((target, options))
            return _reply(200)

        p.login = login
        p.request = request
        with mock.patch.object(regressions.labkit, "loopback_source", side_effect=_source):
            regressions.other_address_unaffected(p)

        self.assertEqual(logins[0][1], "127.0.2.2")
        target, options = sent[0]
        self.assertEqual(target, f"/api/search?q={quote(regressions.B11_TERMS[20], safe='')}")
        self.assertTrue(options["scored"])


class WordsAndStatusesTests(unittest.TestCase):
    def test_the_words_are_distinct_and_none_is_one_of_the_p0_2_budget_words(self):
        words = regressions.B11_TERMS
        self.assertEqual(len(words), 2 * regressions.FORGED_SESSIONS - 1)
        self.assertEqual(len(set(words)), len(words))
        self.assertFalse(set(words) & set(regressions.BUDGET_TERMS))

    def test_the_forged_credentials_have_the_shape_of_the_forged_sid_and_differ(self):
        names = [regressions._forged(index) for index in range(1, regressions.FORGED_SESSIONS + 1)]
        self.assertEqual(len(set(names)), regressions.FORGED_SESSIONS)
        self.assertTrue(all(len(name) == len(regressions.FORGED_SID) - len("SID=") for name in names))

    def test_the_second_injection_is_not_the_one_p0_2_sends(self):
        self.assertNotEqual(regressions._second_sqli(), probes.first_attack("sqli"))

    def test_the_two_cases_have_the_statuses_of_the_plan_and_run_on_the_limit_site(self):
        by_name = {case.name: case for case in regressions.CASES}
        total = by_name["b11-forged-sessions-total-cap"]
        self.assertEqual((total.status, total.expect, total.reason, total.site),
                         ("must", "block", "limit", lab.SITE_LIMIT))
        other = by_name["b11-other-address-unaffected"]
        self.assertEqual((other.status, other.expect, other.reason, other.site),
                         ("must", "allow", None, lab.SITE_LIMIT))


if __name__ == "__main__":
    unittest.main()
