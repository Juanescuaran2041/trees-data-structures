from __future__ import annotations

from collections import deque
from collections.abc import Iterator

from ransomware_lab.telemetry import BehaviorVector


class ProcessLineageError(ValueError):
    pass


class MonitoredProcess:
    def __init__(
        self,
        pid: int,
        image_name: str,
        behavior: BehaviorVector,
        ground_truth_profile: str,
    ) -> None:
        self._pid = pid
        self._image_name = image_name
        self._behavior = behavior
        self._ground_truth_profile = ground_truth_profile
        self._parent: MonitoredProcess | None = None
        self._children: list[MonitoredProcess] = []

    @property
    def pid(self) -> int:
        return self._pid

    @property
    def image_name(self) -> str:
        return self._image_name

    @property
    def behavior(self) -> BehaviorVector:
        return self._behavior

    @property
    def ground_truth_profile(self) -> str:
        return self._ground_truth_profile

    @property
    def parent(self) -> MonitoredProcess | None:
        return self._parent

    @property
    def children(self) -> tuple[MonitoredProcess, ...]:
        return tuple(self._children)

    @property
    def is_root(self) -> bool:
        return self._parent is None

    @property
    def is_leaf(self) -> bool:
        return not self._children

    @property
    def depth(self) -> int:
        return sum(1 for _ in self.ancestors())

    @property
    def subtree_size(self) -> int:
        return sum(1 for _ in self.depth_first())

    def observe(self, behavior: BehaviorVector) -> None:
        self._behavior = behavior

    def spawn(self, child: MonitoredProcess) -> MonitoredProcess:
        if child is self or child in self.ancestors():
            raise ProcessLineageError(f"pid {child.pid} would create a cycle under pid {self._pid}")
        if child._parent is not None:
            raise ProcessLineageError(f"pid {child.pid} already has parent pid {child._parent.pid}")
        child._parent = self
        self._children.append(child)
        return child

    def ancestors(self) -> Iterator[MonitoredProcess]:
        cursor = self._parent
        while cursor is not None:
            yield cursor
            cursor = cursor._parent

    def depth_first(self) -> Iterator[MonitoredProcess]:
        pending = [self]
        while pending:
            current = pending.pop()
            yield current
            pending.extend(reversed(current._children))

    def breadth_first(self) -> Iterator[MonitoredProcess]:
        queue: deque[MonitoredProcess] = deque([self])
        while queue:
            current = queue.popleft()
            yield current
            queue.extend(current._children)

    def __repr__(self) -> str:
        return f"MonitoredProcess(pid={self._pid}, image_name={self._image_name!r})"


class ProcessTree:
    def __init__(self, root: MonitoredProcess) -> None:
        self._root = root
        self._by_pid: dict[int, MonitoredProcess] = {root.pid: root}

    @property
    def root(self) -> MonitoredProcess:
        return self._root

    def __len__(self) -> int:
        return len(self._by_pid)

    def __iter__(self) -> Iterator[MonitoredProcess]:
        return self._root.breadth_first()

    def __contains__(self, pid: object) -> bool:
        return pid in self._by_pid

    def attach(self, parent_pid: int, child: MonitoredProcess) -> MonitoredProcess:
        if child.pid in self._by_pid:
            raise ProcessLineageError(f"pid {child.pid} is already registered")
        self.require(parent_pid).spawn(child)
        self._by_pid[child.pid] = child
        return child

    def find(self, pid: int) -> MonitoredProcess | None:
        return self._by_pid.get(pid)

    def require(self, pid: int) -> MonitoredProcess:
        process = self._by_pid.get(pid)
        if process is None:
            raise ProcessLineageError(f"unknown pid {pid}")
        return process

    def lineage_of(self, pid: int) -> tuple[MonitoredProcess, ...]:
        process = self.require(pid)
        return (*reversed(tuple(process.ancestors())), process)

    def height(self) -> int:
        return 1 + max(process.depth for process in self)
