"""Edge model representing directed relationships in the attack graph."""

from typing import Dict, Any, Optional


class Edge:
    """Represents a directed link (e.g. EXPOSES, RUNS, HAS_FINDING) between two nodes."""

    def __init__(
        self,
        source: str,
        target: str,
        relation: str,
        risk: str = "LOW",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.source = source
        self.target = target
        self.relation = relation
        self.risk = risk
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "risk": self.risk,
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        return f"Edge({self.source} -> {self.target} [{self.relation}])"
