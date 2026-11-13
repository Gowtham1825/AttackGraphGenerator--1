"""Node model for the attack graph."""

from typing import Dict, Any, Optional


class Node:
    """Represents a discrete entity (HOST, PORT, SERVICE, FINDING) in the attack graph."""

    def __init__(
        self,
        node_id: str,
        label: str,
        node_type: str,
        risk: str = "LOW",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.node_id = node_id
        self.label = label
        self.node_type = node_type
        self.risk = risk
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.node_id,
            "label": self.label,
            "type": self.node_type,
            "risk": self.risk,
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        return f"Node(id='{self.node_id}', type='{self.node_type}', risk='{self.risk}')"
