from __future__ import annotations

import pytest

from ransomware_lab.process_tree import MonitoredProcess, ProcessLineageError, ProcessTree
from ransomware_lab.telemetry import BehaviorFeature, BehaviorVector

QUIET = BehaviorVector.from_mapping({feature: 0.0 for feature in BehaviorFeature})


def process(pid: int) -> MonitoredProcess:
    return MonitoredProcess(pid, f"p{pid}.exe", QUIET, "office-workload")


def sample_tree() -> ProcessTree:
    tree = ProcessTree(process(4))
    tree.attach(4, process(10))
    tree.attach(10, process(20))
    tree.attach(10, process(21))
    tree.attach(4, process(11))
    return tree


def test_breadth_first_visits_level_by_level():
    assert [node.pid for node in sample_tree()] == [4, 10, 11, 20, 21]


def test_depth_first_follows_each_branch_to_its_end():
    assert [node.pid for node in sample_tree().root.depth_first()] == [4, 10, 20, 21, 11]


def test_lineage_runs_from_the_root_to_the_process():
    assert [node.pid for node in sample_tree().lineage_of(20)] == [4, 10, 20]


def test_depth_and_subtree_size_describe_the_shape():
    tree = sample_tree()
    assert tree.root.depth == 0
    assert tree.require(20).depth == 2
    assert tree.require(10).subtree_size == 3
    assert tree.height() == 3
    assert len(tree) == 5


def test_leaves_and_root_are_identified():
    tree = sample_tree()
    assert tree.root.is_root
    assert tree.require(21).is_leaf
    assert not tree.require(10).is_leaf


def test_duplicate_pid_is_rejected():
    tree = sample_tree()
    with pytest.raises(ProcessLineageError):
        tree.attach(4, process(10))


def test_unknown_parent_is_rejected():
    with pytest.raises(ProcessLineageError):
        sample_tree().attach(999, process(50))


def test_reparenting_an_attached_process_is_rejected():
    tree = sample_tree()
    with pytest.raises(ProcessLineageError):
        tree.require(11).spawn(tree.require(20))


def test_a_process_cannot_become_its_own_ancestor():
    tree = sample_tree()
    with pytest.raises(ProcessLineageError):
        tree.require(20).spawn(tree.require(4))


def test_find_returns_none_for_an_unknown_pid():
    tree = sample_tree()
    assert tree.find(123) is None
    assert 20 in tree
