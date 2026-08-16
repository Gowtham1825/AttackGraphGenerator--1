class Edge:
    """
    Represents a relationship between two nodes
    in the security attack graph.

    Examples:
        HOST -> PORT
        PORT -> SERVICE
        PORT -> FINDING
        FINDING -> RISK
    """

    def __init__(
        self,
        source,
        target,
        relation,
        risk="LOW",
        metadata=None
    ):

        self.source = source
        self.target = target
        self.relation = relation

        self.risk = risk

        self.metadata = (
            metadata
            if metadata is not None
            else {}
        )

    def to_dict(self):
        """
        Convert the edge into a JSON-compatible dictionary.
        """

        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "risk": self.risk,
            "metadata": self.metadata
        }

    def __repr__(self):

        return (
            f"Edge("
            f"source='{self.source}', "
            f"target='{self.target}', "
            f"relation='{self.relation}', "
            f"risk='{self.risk}'"
            f")"
        )