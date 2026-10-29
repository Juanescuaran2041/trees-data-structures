from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from itertools import count


@dataclass(frozen=True, slots=True)
class TriageTicket:
    pid: int
    image_name: str
    risk: float
    lineage_depth: int
    arrival: int = field(default=0, compare=False)

    @property
    def priority(self) -> tuple[float, int]:
        # Higher risk first; on a tie the older ticket wins, so the queue stays FIFO-stable.
        return (self.risk, -self.arrival)

    def outranks(self, other: TriageTicket) -> bool:
        return self.priority > other.priority


class ThreatTriageQueue:
    def __init__(self) -> None:
        self._tickets: list[TriageTicket] = []
        self._arrivals = count()

    def __len__(self) -> int:
        return len(self._tickets)

    def __bool__(self) -> bool:
        return bool(self._tickets)

    def __iter__(self) -> Iterator[TriageTicket]:
        return iter(self._tickets)

    def admit(self, pid: int, image_name: str, risk: float, lineage_depth: int) -> TriageTicket:
        ticket = TriageTicket(pid, image_name, risk, lineage_depth, next(self._arrivals))
        self._tickets.append(ticket)
        self._sift_up(len(self._tickets) - 1)
        return ticket

    def peek(self) -> TriageTicket | None:
        return self._tickets[0] if self._tickets else None

    def pop(self) -> TriageTicket:
        if not self._tickets:
            raise IndexError("the triage queue is empty")
        root = self._tickets[0]
        last = self._tickets.pop()
        if self._tickets:
            self._tickets[0] = last
            self._sift_down(0)
        return root

    def drain(self) -> tuple[TriageTicket, ...]:
        return tuple(self.pop() for _ in range(len(self._tickets)))

    def most_critical(self, limit: int) -> tuple[TriageTicket, ...]:
        mirror = ThreatTriageQueue()
        mirror._tickets = list(self._tickets)
        return tuple(mirror.pop() for _ in range(min(limit, len(mirror))))

    def holds_heap_invariant(self) -> bool:
        return all(
            not self._tickets[child].outranks(self._tickets[(child - 1) // 2])
            for child in range(1, len(self._tickets))
        )

    def _sift_up(self, position: int) -> None:
        while position > 0:
            parent = (position - 1) // 2
            if not self._tickets[position].outranks(self._tickets[parent]):
                return
            self._swap(position, parent)
            position = parent

    def _sift_down(self, position: int) -> None:
        size = len(self._tickets)
        while True:
            winner = position
            for child in (2 * position + 1, 2 * position + 2):
                if child < size and self._tickets[child].outranks(self._tickets[winner]):
                    winner = child
            if winner == position:
                return
            self._swap(position, winner)
            position = winner

    def _swap(self, left: int, right: int) -> None:
        self._tickets[left], self._tickets[right] = self._tickets[right], self._tickets[left]
