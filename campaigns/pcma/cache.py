"""Explicit root-scoped PCMA client cache with simple deterministic policies."""
from collections import OrderedDict

from core import CACHE_RECORD_BYTES, NodeKey


class NodeCache:
    def __init__(self, budget_bytes: int | None, policy: str):
        if policy not in {"lru", "upper-level", "full"}:
            raise ValueError("policy must be lru, upper-level, or full")
        if budget_bytes is not None and budget_bytes < 0:
            raise ValueError("cache budget cannot be negative")
        self.budget_bytes = budget_bytes
        self.policy = policy
        self._nodes: OrderedDict[NodeKey, bytes] = OrderedDict()
        self.hits = 0
        self.misses = 0

    @property
    def capacity(self):
        return None if self.budget_bytes is None else self.budget_bytes // CACHE_RECORD_BYTES

    @property
    def bytes(self):
        return len(self._nodes) * CACHE_RECORD_BYTES

    def advertised_keys(self, root: bytes):
        return tuple(key for key in self._nodes if key.root == root)

    def values(self):
        return dict(self._nodes)

    def account(self, required):
        for key in required:
            if key in self._nodes:
                self.hits += 1
                if self.policy == "lru": self._nodes.move_to_end(key)
            else:
                self.misses += 1

    def update(self, nodes):
        for key, value in nodes.items():
            if key in self._nodes:
                if self._nodes[key] != value:
                    raise ValueError("authenticated node changed under the same root")
                if self.policy == "lru": self._nodes.move_to_end(key)
            else:
                self._nodes[key] = value
        while self.capacity is not None and len(self._nodes) > self.capacity:
            if self.policy == "lru":
                self._nodes.popitem(last=False)
            else:
                victim = min(self._nodes, key=lambda key: (key.level, next(i for i, k in enumerate(self._nodes) if k == key)))
                del self._nodes[victim]
