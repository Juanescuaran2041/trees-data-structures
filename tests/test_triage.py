from __future__ import annotations

from random import Random

import pytest

from ransomware_lab.triage import ThreatTriageQueue


def test_pops_the_highest_risk_first():
    queue = ThreatTriageQueue()
    queue.admit(100, "a.exe", 0.40, 1)
    queue.admit(200, "b.exe", 0.95, 2)
    queue.admit(300, "c.exe", 0.70, 1)
    assert [ticket.pid for ticket in queue.drain()] == [200, 300, 100]


def test_equal_risk_keeps_arrival_order():
    queue = ThreatTriageQueue()
    for pid in (10, 20, 30, 40):
        queue.admit(pid, f"p{pid}.exe", 0.8, 1)
    assert [ticket.pid for ticket in queue.drain()] == [10, 20, 30, 40]


def test_invariant_holds_after_random_traffic():
    queue = ThreatTriageQueue()
    noise = Random(1234)
    for pid in range(400):
        queue.admit(pid, f"p{pid}.exe", noise.random(), noise.randint(0, 6))
        assert queue.holds_heap_invariant()
        if noise.random() < 0.3:
            queue.pop()
            assert queue.holds_heap_invariant()


def test_draining_yields_a_non_increasing_risk_sequence():
    queue = ThreatTriageQueue()
    noise = Random(99)
    for pid in range(200):
        queue.admit(pid, "p.exe", noise.random(), 0)
    risks = [ticket.risk for ticket in queue.drain()]
    assert risks == sorted(risks, reverse=True)
    assert not queue


def test_peek_does_not_consume_and_most_critical_leaves_the_queue_intact():
    queue = ThreatTriageQueue()
    queue.admit(1, "low.exe", 0.1, 0)
    queue.admit(2, "high.exe", 0.9, 0)
    assert queue.peek().pid == 2
    assert [ticket.pid for ticket in queue.most_critical(2)] == [2, 1]
    assert len(queue) == 2


def test_popping_an_empty_queue_fails_loudly():
    with pytest.raises(IndexError):
        ThreatTriageQueue().pop()
