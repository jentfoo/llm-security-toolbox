"""Smoke tests for controller loop internals.

These tests exercise the message-building and decision-dispatch paths
with a scripted fake ClaudeSDKClient — no network, no real SDK.
"""

import asyncio
import tempfile
import unittest
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)

import controller
from findings import FindingWriter
from tools import (
    CandidatePool,
    DecisionQueue,
    FindingFiled,
    ToolCallRecord,
    WorkerDecision,
    WorkerTurnSummary,
)


def _result(cost: float = 0.01) -> ResultMessage:
    return ResultMessage(
        subtype="result",
        duration_ms=0,
        duration_api_ms=0,
        is_error=False,
        num_turns=1,
        session_id="test",
        total_cost_usd=cost,
    )


class FakeSDKClient:
    """Minimal async fake of ClaudeSDKClient for testing."""

    def __init__(self, scripts: list[list[Any]]):
        self._scripts = list(scripts)
        self.queries: list[str] = []

    async def query(self, content: str) -> None:
        self.queries.append(content)

    def receive_response(self):
        if not self._scripts:
            raise AssertionError("No more scripted turns")
        messages = self._scripts.pop(0)

        async def gen():
            for m in messages:
                yield m

        return gen()

    async def interrupt(self) -> None:
        pass


class _StubClient:
    def __init__(self):
        self.queries: list[str] = []

    async def query(self, msg: str) -> None:
        self.queries.append(msg)


def _run(coro):
    return asyncio.run(coro)


class TestCollectWorkerTurn(unittest.TestCase):
    def test_captures_text_and_tools(self):
        pool = CandidatePool()
        client = FakeSDKClient([
            [
                AssistantMessage(
                    content=[
                        TextBlock(text="Tested /search. Found reflection."),
                        ToolUseBlock(
                            id="u1",
                            name="mcp__sectool__replay_send",
                            input={"flow_id": "abc123", "mutations": {}},
                        ),
                    ],
                    model="test",
                ),
                UserMessage(content=[
                    ToolResultBlock(
                        tool_use_id="u1",
                        content=[{"type": "text", "text": "Replayed. new flow_id: xyz789"}],
                    ),
                ]),
                _result(0.02),
            ],
        ])
        s = _run(controller.collect_worker_turn(client, worker_id=1, iteration=1, candidates=pool))
        self.assertEqual(s.worker_id, 1)
        self.assertIn("Tested /search", s.assistant_text)
        self.assertEqual(len(s.tool_calls), 1)
        self.assertEqual(s.tool_calls[0].name, "mcp__sectool__replay_send")
        self.assertIn("Replayed", s.tool_calls[0].result_summary)
        self.assertIn("abc123", s.flow_ids_touched)
        self.assertIn("xyz789", s.flow_ids_touched)
        self.assertEqual(s.cost_usd, 0.02)

    def test_attributes_candidates_to_active_worker(self):
        pool = CandidatePool()
        # Pre-seed a prior candidate to verify ids_since returns only new ones
        pool.add(title="old", severity="low", endpoint="/a",
                 flow_ids=["aaaa11"], summary="", evidence_notes="", reproduction_hint="")

        class PoolSideEffectClient(FakeSDKClient):
            def receive_response(self_inner):
                async def gen():
                    for m in self_inner._scripts.pop(0):
                        yield m
                        if isinstance(m, AssistantMessage) and any(
                            isinstance(b, ToolUseBlock)
                            and b.name == "mcp__worker_tools__report_finding_candidate"
                            for b in m.content
                        ):
                            # Simulate tool handler side effect
                            pool.add(title="new", severity="high", endpoint="/b",
                                     flow_ids=["bbbb22"], summary="",
                                     evidence_notes="", reproduction_hint="")
                return gen()

        client = PoolSideEffectClient([
            [
                AssistantMessage(
                    content=[
                        TextBlock(text="Reporting."),
                        ToolUseBlock(
                            id="u1",
                            name="mcp__worker_tools__report_finding_candidate",
                            input={"title": "new"},
                        ),
                    ],
                    model="test",
                ),
                UserMessage(content=[
                    ToolResultBlock(tool_use_id="u1",
                                    content=[{"type": "text", "text": "Candidate c002 recorded."}]),
                ]),
                _result(),
            ],
        ])
        s = _run(controller.collect_worker_turn(client, worker_id=2, iteration=3, candidates=pool))
        self.assertEqual(s.candidate_ids, ["c002"])
        self.assertEqual(pool.get("c002").worker_id, 2)


class TestApplyDecision(unittest.TestCase):
    def _make_worker(self):
        w = controller.WorkerState(worker_id=7, options=None)
        w.client = _StubClient()
        return w

    def test_continue_with_none_increments_streak(self):
        w = self._make_worker()
        d = WorkerDecision(kind="continue", worker_id=7, instruction="go", progress="none")
        _run(controller.apply_decision(d, w, iteration=5))
        self.assertEqual(w.progress_none_streak, 1)
        self.assertEqual(w.last_instruction, "go")
        self.assertEqual(w.client.queries, ["go"])

    def test_new_progress_resets_streak_and_warning(self):
        w = self._make_worker()
        w.progress_none_streak = 3
        w.stall_warned = True
        d = WorkerDecision(kind="expand", worker_id=7, instruction="pivot", progress="new")
        _run(controller.apply_decision(d, w, iteration=5))
        self.assertEqual(w.progress_none_streak, 0)
        self.assertFalse(w.stall_warned)

    def test_stop_tears_down(self):
        w = self._make_worker()
        d = WorkerDecision(kind="stop", worker_id=7, reason="coverage complete")
        _run(controller.apply_decision(d, w, iteration=5))
        self.assertFalse(w.alive)


class TestMessageFormatting(unittest.TestCase):
    def test_pending_candidates_empty(self):
        pool = CandidatePool()
        self.assertEqual(controller._format_pending_candidates(pool), "No pending finding candidates.")

    def test_pending_candidates_populated(self):
        pool = CandidatePool()
        pool.add(title="XSS in search", severity="high", endpoint="GET /search",
                 flow_ids=["abcdef"], summary="reflection in q",
                 evidence_notes="script tag echoed", reproduction_hint="replay abcdef")
        out = controller._format_pending_candidates(pool)
        self.assertIn("c001", out)
        self.assertIn("XSS in search", out)
        self.assertIn("abcdef", out)

    def test_build_orch_message_contents(self):
        pool = CandidatePool()
        pool.add(title="T", severity="low", endpoint="/x",
                 flow_ids=["zz1122"], summary="s",
                 evidence_notes="e", reproduction_hint="r")
        ws = WorkerTurnSummary(
            worker_id=1, iteration=2,
            assistant_text="ran tests",
            tool_calls=[ToolCallRecord(name="mcp__sectool__proxy_poll",
                                       input_summary="{}",
                                       result_summary="5 flows")],
            flow_ids_touched=["zz1122"],
        )
        msg = controller._build_orch_message(
            iteration=2, max_iter=10,
            total_cost=0.5, max_cost=5.0,
            findings_summary="No findings filed yet.",
            findings_count=0,
            pending_candidates_text=controller._format_pending_candidates(pool),
            stall_warnings="",
            worker_summaries=[ws],
        )
        self.assertIn("iteration 2/10", msg)
        self.assertIn("cost $0.50/$5.00", msg)
        self.assertIn("findings filed: 0", msg)
        self.assertIn("Pending finding candidates", msg)
        self.assertIn("mcp__sectool__proxy_poll", msg)


class TestFindingLifecycle(unittest.TestCase):
    def test_finding_and_dismissal_drains(self):
        pool = CandidatePool()
        decisions = DecisionQueue()
        c1 = pool.add(title="XSS", severity="high", endpoint="GET /s",
                      flow_ids=["aaaa11"], summary="", evidence_notes="",
                      reproduction_hint="")
        c2 = pool.add(title="SQLi", severity="critical", endpoint="POST /l",
                      flow_ids=["bbbb22"], summary="", evidence_notes="",
                      reproduction_hint="")

        decisions.add_finding(FindingFiled(
            title="Reflected XSS", severity="high", endpoint="GET /s",
            description="d", reproduction_steps="r", evidence="e", impact="i",
            verification_notes="replayed aaaa11 with payload — got reflection",
            supersedes_candidate_ids=[c1],
        ))
        decisions.add_dismissal(c2, "already covered")
        decisions.set_done("coverage complete")

        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            for f in decisions.findings:
                if not fw.is_duplicate(f):
                    fw.write(f)
                    for cid in f.supersedes_candidate_ids:
                        pool.mark(cid, "verified")
            for dm in decisions.dismissals:
                pool.mark(dm.candidate_id, "dismissed")

        self.assertEqual(fw.count, 1)
        self.assertEqual(pool.get(c1).status, "verified")
        self.assertEqual(pool.get(c2).status, "dismissed")
        self.assertEqual(pool.pending(), [])
        self.assertEqual(decisions.done_summary, "coverage complete")

    def test_duplicate_finding_still_resolves_candidates(self):
        """If a finding's doc is a dup, its candidates must still be marked
        verified — otherwise they stay pending forever and pollute every
        subsequent orchestrator prompt."""
        pool = CandidatePool()
        c1 = pool.add(title="XSS", severity="high", endpoint="GET /s",
                      flow_ids=["aaaa11"], summary="", evidence_notes="",
                      reproduction_hint="")
        c2 = pool.add(title="XSS dup", severity="high", endpoint="GET /s",
                      flow_ids=["bbbb22"], summary="", evidence_notes="",
                      reproduction_hint="")

        filed_first = FindingFiled(
            title="Reflected XSS", severity="high", endpoint="GET /s",
            description="d", reproduction_steps="r", evidence="e", impact="i",
            verification_notes="v1", supersedes_candidate_ids=[c1],
        )
        filed_dup = FindingFiled(
            title="Reflected XSS", severity="high", endpoint="GET /s",
            description="d", reproduction_steps="r", evidence="e", impact="i",
            verification_notes="v2", supersedes_candidate_ids=[c2],
        )

        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            # Replicate controller loop's finding application.
            for filed in (filed_first, filed_dup):
                if not fw.is_duplicate(filed):
                    fw.write(filed)
                for cid in filed.supersedes_candidate_ids:
                    pool.mark(cid, "verified")

        self.assertEqual(fw.count, 1)  # second one was a dup
        self.assertEqual(pool.get(c1).status, "verified")
        self.assertEqual(pool.get(c2).status, "verified")
        self.assertEqual(pool.pending(), [])


if __name__ == "__main__":
    unittest.main()
