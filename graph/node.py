class Node:
    """
    Represents a node in the security attack graph.

    A node can represent:
    - HOST
    - PORT
    - FINDING
    - SERVICE
    """

    def __init__(
        self,
        node_id,
        label,
        node_type,
        risk="LOW",
        metadata=None
    ):

        self.node_id = node_id
        self.label = label
        self.node_type = node_type

        self.risk = risk

        self.metadata = (
            metadata
            if metadata is not None
            else {}
        )

    def to_dict(self):
        """
        Convert node into a JSON-compatible dictionary.
        """

        return {
            "id": self.node_id,
            "label": self.label,
            "type": self.node_type,
            "risk": self.risk,
            "metadata": self.metadata
        }

    def __repr__(self):

        return (
            f"Node("
            f"id='{self.node_id}', "
            f"label='{self.label}', "
            f"type='{self.node_type}', "
            f"risk='{self.risk}'"
            f")"
        )