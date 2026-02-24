"""Unit tests for tools.py — queue recording and flow ID extraction."""

import unittest

from tools import (
    CandidateDismissal,
    CandidatePool,
    DecisionQueue,
    FindingFiled,
    PlanEntry,
    WorkerDecision,
    extract_flow_ids,
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

    def test_active_worker_attribution(self):
        p = CandidatePool()
        p.active_worker_id = 3
        cid = p.add(title="T", severity="medium", endpoint="/z", flow_ids=["qq11rr"],
                    summary="s", evidence_notes="e", reproduction_hint="r")
        self.assertEqual(p.get(cid).worker_id, 3)

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


class TestDecisionQueue(unittest.TestCase):
    def test_reset_clears_all(self):
        q = DecisionQueue()
        q.set_plan([PlanEntry(1, "x")])
        q.add_decision(WorkerDecision(kind="continue", worker_id=1, instruction="i", progress="new"))
        q.add_finding(FindingFiled(title="T", severity="high", endpoint="/", description="",
                                    reproduction_steps="", evidence="", impact="",
                                    verification_notes="v"))
        q.add_dismissal("c001", "false positive")
        q.set_done("wrap")
        q.reset()
        self.assertIsNone(q.plan)
        self.assertEqual(q.worker_decisions, [])
        self.assertEqual(q.findings, [])
        self.assertEqual(q.dismissals, [])
        self.assertIsNone(q.done_summary)

    def test_dismissal_appends(self):
        q = DecisionQueue()
        q.add_dismissal("c007", "dup")
        self.assertEqual(q.dismissals, [CandidateDismissal(candidate_id="c007", reason="dup")])


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


if __name__ == "__main__":
    unittest.main()
