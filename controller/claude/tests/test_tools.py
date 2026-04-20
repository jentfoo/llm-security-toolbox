"""Unit tests for tools.py — queue recording, phase gating, and flow IDs."""

import asyncio
import unittest

from tools import (
    CandidateDismissal,
    CandidatePool,
    DEFAULT_AUTONOMOUS_BUDGET,
    DecisionQueue,
    FindingFiled,
    MAX_AUTONOMOUS_BUDGET,
    PHASE_DIRECTION,
    PHASE_IDLE,
    PHASE_VERIFICATION,
    PlanEntry,
    WorkerDecision,
    _reject_wrong_phase,
    current_worker_id,
    extract_flow_ids,
    reset_active_worker,
    set_active_worker,
)


class TestCandidatePool(unittest.TestCase):
    def test_add_sequences_ids(self):
        p = CandidatePool()
        c1 = p.add(title="A", severity="high", endpoint="/x", flow_ids=["ab12cd"],
                   summary="s", evidence_notes="e", reproduction_hint="r")
        c2 = p.add(title="B", severity="low", endpoint="/y", flow_ids=["ef34gh"],
                   summary="s", evidence_notes="e", reproduction_hint="r")
        self.assertEqual(c1, "c001")
        self.assertEqual(c2, "c002")

    def test_contextvar_attribution(self):
        p = CandidatePool()
        token = set_active_worker(3)
        try:
            cid = p.add(title="T", severity="medium", endpoint="/z", flow_ids=["qq11rr"],
                        summary="s", evidence_notes="e", reproduction_hint="r")
        finally:
            reset_active_worker(token)
        self.assertEqual(p.get(cid).worker_id, 3)

    def test_contextvar_isolates_concurrent_tasks(self):
        """Each asyncio task sees its own active_worker_id."""
        p = CandidatePool()

        async def add_as(worker_id: int, title: str, delay: float) -> str:
            token = set_active_worker(worker_id)
            try:
                await asyncio.sleep(delay)  # interleave tasks
                return p.add(title=title, severity="low", endpoint="/",
                             flow_ids=["aaaa11"], summary="",
                             evidence_notes="", reproduction_hint="")
            finally:
                reset_active_worker(token)

        async def run_both():
            return await asyncio.gather(
                add_as(1, "from-1", 0.01),
                add_as(2, "from-2", 0.0),
            )

        cid_a, cid_b = asyncio.run(run_both())
        self.assertEqual(p.get(cid_a).worker_id, 1)
        self.assertEqual(p.get(cid_b).worker_id, 2)

    def test_current_worker_id_default_none(self):
        self.assertIsNone(current_worker_id())

    def test_pending_excludes_verified_and_dismissed(self):
        p = CandidatePool()
        c1 = p.add(title="A", severity="high", endpoint="/x", flow_ids=["a1b2c3"],
                   summary="", evidence_notes="", reproduction_hint="")
        c2 = p.add(title="B", severity="low", endpoint="/y", flow_ids=["d4e5f6"],
                   summary="", evidence_notes="", reproduction_hint="")
        c3 = p.add(title="C", severity="low", endpoint="/z", flow_ids=["g7h8i9"],
                   summary="", evidence_notes="", reproduction_hint="")
        p.mark(c1, "verified")
        p.mark(c3, "dismissed")
        self.assertEqual([c.candidate_id for c in p.pending()], [c2])

    def test_ids_since(self):
        p = CandidatePool()
        p.add(title="a", severity="low", endpoint="/", flow_ids=["aaaa11"],
              summary="", evidence_notes="", reproduction_hint="")
        before = p.counter
        p.add(title="b", severity="low", endpoint="/", flow_ids=["bbbb22"],
              summary="", evidence_notes="", reproduction_hint="")
        p.add(title="c", severity="low", endpoint="/", flow_ids=["cccc33"],
              summary="", evidence_notes="", reproduction_hint="")
        self.assertEqual(p.ids_since(before), ["c002", "c003"])

    def test_ids_since_for_worker_filters(self):
        p = CandidatePool()
        # Worker 1 adds one
        token = set_active_worker(1)
        try:
            p.add(title="w1", severity="low", endpoint="/", flow_ids=["aaaa11"],
                  summary="", evidence_notes="", reproduction_hint="")
        finally:
            reset_active_worker(token)
        before = p.counter
        # Worker 2 adds two
        token = set_active_worker(2)
        try:
            p.add(title="w2a", severity="low", endpoint="/", flow_ids=["bbbb22"],
                  summary="", evidence_notes="", reproduction_hint="")
            p.add(title="w2b", severity="low", endpoint="/", flow_ids=["cccc33"],
                  summary="", evidence_notes="", reproduction_hint="")
        finally:
            reset_active_worker(token)
        # Worker 1 adds another
        token = set_active_worker(1)
        try:
            p.add(title="w1b", severity="low", endpoint="/", flow_ids=["dddd44"],
                  summary="", evidence_notes="", reproduction_hint="")
        finally:
            reset_active_worker(token)

        self.assertEqual(p.ids_since_for_worker(before, 2), ["c002", "c003"])
        self.assertEqual(p.ids_since_for_worker(before, 1), ["c004"])
        self.assertEqual(p.ids_since_for_worker(before, 99), [])


class TestDecisionQueuePhases(unittest.TestCase):
    def test_reset_clears_all(self):
        q = DecisionQueue()
        q.begin_phase(PHASE_DIRECTION)
        q.set_plan([PlanEntry(1, "x")])
        q.add_decision(WorkerDecision(kind="continue", worker_id=1, instruction="i", progress="new"))
        q.begin_phase(PHASE_VERIFICATION)
        q.add_finding(FindingFiled(title="T", severity="high", endpoint="/", description="",
                                    reproduction_steps="", evidence="", impact="",
                                    verification_notes="v"))
        q.add_dismissal("c001", "false positive")
        q.set_verification_done("verified")
        q.begin_phase(PHASE_DIRECTION)
        q.set_direction_done("directed")
        q.set_done("wrap")

        q.reset()
        self.assertIsNone(q.plan)
        self.assertEqual(q.worker_decisions, [])
        self.assertEqual(q.findings, [])
        self.assertEqual(q.dismissals, [])
        self.assertIsNone(q.done_summary)
        self.assertIsNone(q.verification_done_summary)
        self.assertIsNone(q.direction_done_summary)
        self.assertEqual(q.phase, PHASE_IDLE)

    def test_begin_phase_transitions(self):
        q = DecisionQueue()
        self.assertEqual(q.current_phase, PHASE_IDLE)
        q.begin_phase(PHASE_VERIFICATION)
        self.assertEqual(q.current_phase, PHASE_VERIFICATION)
        q.set_verification_done("ok")
        self.assertEqual(q.verification_done_summary, "ok")
        # Re-entering a phase clears only its own done flag
        q.begin_phase(PHASE_VERIFICATION)
        self.assertIsNone(q.verification_done_summary)

    def test_begin_phase_does_not_clear_other_accumulators(self):
        q = DecisionQueue()
        q.begin_phase(PHASE_VERIFICATION)
        q.add_finding(FindingFiled(title="T", severity="high", endpoint="/", description="",
                                    reproduction_steps="", evidence="", impact="",
                                    verification_notes="v"))
        q.begin_phase(PHASE_DIRECTION)
        self.assertEqual(len(q.findings), 1)  # findings accumulate across phase switches within an iter


class TestRejectWrongPhase(unittest.TestCase):
    def test_shape(self):
        out = _reject_wrong_phase(PHASE_DIRECTION, PHASE_VERIFICATION, "plan_workers")
        self.assertTrue(out["is_error"])
        self.assertIn("plan_workers", out["content"][0]["text"])
        self.assertIn("verification", out["content"][0]["text"])
        self.assertIn("verification_done", out["content"][0]["text"])

    def test_reverse(self):
        out = _reject_wrong_phase(PHASE_VERIFICATION, PHASE_DIRECTION, "file_finding")
        self.assertTrue(out["is_error"])
        self.assertIn("file_finding", out["content"][0]["text"])


class TestWorkerDecisionDefaults(unittest.TestCase):
    def test_autonomous_budget_default(self):
        d = WorkerDecision(kind="continue", worker_id=1, instruction="go", progress="new")
        self.assertEqual(d.autonomous_budget, DEFAULT_AUTONOMOUS_BUDGET)

    def test_autonomous_budget_override(self):
        d = WorkerDecision(kind="continue", worker_id=1, instruction="go",
                           progress="new", autonomous_budget=10)
        self.assertEqual(d.autonomous_budget, 10)

    def test_autonomous_budget_constants(self):
        self.assertGreaterEqual(MAX_AUTONOMOUS_BUDGET, DEFAULT_AUTONOMOUS_BUDGET)
        self.assertGreater(DEFAULT_AUTONOMOUS_BUDGET, 0)


class TestExtractFlowIds(unittest.TestCase):
    def test_text_keyword_patterns(self):
        text = (
            "I opened flow_id=abcdef and also source_flow_id: DEF456. "
            'Nested: flow_a="xy12zz", flow_b=11qq2.'
        )
        ids = extract_flow_ids(text)
        for expected in ("abcdef", "DEF456", "xy12zz", "11qq2"):
            self.assertIn(expected, ids)

    def test_dict_flow_id_field(self):
        d = {"flow_id": "id0001", "inner": {"source_flow_id": "id0002"}}
        ids = extract_flow_ids(d)
        self.assertIn("id0001", ids)
        self.assertIn("id0002", ids)

    def test_list_of_dicts(self):
        lst = [{"flow_id": "aaaa11"}, {"flow_id": "bbbb22"}]
        ids = extract_flow_ids(lst)
        self.assertEqual(ids, ["aaaa11", "bbbb22"])

    def test_dedup_and_order_preserved(self):
        ids = extract_flow_ids(
            "flow_id AAAA11",
            {"flow_id": "BBBB22"},
            "flow_id AAAA11 seen again",
            {"flow_id": "CCCC33"},
        )
        self.assertEqual(ids, ["AAAA11", "BBBB22", "CCCC33"])

    def test_no_match_without_keyword(self):
        ids = extract_flow_ids("I saw ABCDEF and QWERTY as tokens.")
        self.assertEqual(ids, [])

    def test_ignores_none_values(self):
        ids = extract_flow_ids(None, "flow_id zz11aa")
        self.assertEqual(ids, ["zz11aa"])

    def test_bare_flow_in_prose_does_not_match(self):
        self.assertEqual(extract_flow_ids("data flow analysis found an issue"), [])
        self.assertEqual(extract_flow_ids("the flow chart shows"), [])
        self.assertEqual(extract_flow_ids("request flow through the system"), [])


class TestDismissal(unittest.TestCase):
    def test_dismissal_appends(self):
        q = DecisionQueue()
        q.add_dismissal("c007", "dup")
        self.assertEqual(q.dismissals, [CandidateDismissal(candidate_id="c007", reason="dup")])


if __name__ == "__main__":
    unittest.main()
