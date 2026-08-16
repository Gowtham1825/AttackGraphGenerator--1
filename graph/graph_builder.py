from graph.node import Node
from graph.edge import Edge


class GraphBuilder:
    """
    Builds the security attack graph.

    Graph structure:

        HOST
          |
          | EXPOSES
          v
        PORT
          |
          | RUNS
          v
       SERVICE
          |
          | HAS_FINDING
          v
       FINDING
    """

    def __init__(self):

        self.nodes = []
        self.edges = []

        # Fast lookup tables
        self._node_ids = set()
        self._edge_keys = set()

    # ==================================================
    # NODE MANAGEMENT
    # ==================================================

    def add_node(self, node):

        if node.node_id in self._node_ids:
            return

        self.nodes.append(node)
        self._node_ids.add(node.node_id)

    # ==================================================
    # EDGE MANAGEMENT
    # ==================================================

    def add_edge(self, edge):

        edge_key = (
            edge.source,
            edge.target,
            edge.relation
        )

        if edge_key in self._edge_keys:
            return

        self.edges.append(edge)
        self._edge_keys.add(edge_key)

    # ==================================================
    # HOST
    # ==================================================

    def add_host(
        self,
        ip,
        risk="LOW",
        risk_score=0
    ):

        host = Node(
            node_id=f"host:{ip}",
            label=ip,
            node_type="HOST",
            risk=risk,
            metadata={
                "ip": ip,
                "risk_score": risk_score
            }
        )

        self.add_node(host)

        return host

    # ==================================================
    # PORT
    # ==================================================

    def add_port(
        self,
        ip,
        port,
        service="UNKNOWN"
    ):

        host_id = f"host:{ip}"
        port_id = f"{ip}:{port}"

        port_node = Node(
            node_id=port_id,
            label=str(port),
            node_type="PORT",
            metadata={
                "ip": ip,
                "port": port,
                "service": service
            }
        )

        self.add_node(port_node)

        edge = Edge(
            source=host_id,
            target=port_id,
            relation="EXPOSES",
            metadata={
                "port": port
            }
        )

        self.add_edge(edge)

        return port_node

    # ==================================================
    # SERVICE
    # ==================================================

    def add_service(
        self,
        ip,
        port,
        service
    ):

        port_id = f"{ip}:{port}"
        service_id = f"{ip}:{port}:service"

        service_node = Node(
            node_id=service_id,
            label=service,
            node_type="SERVICE",
            metadata={
                "ip": ip,
                "port": port,
                "service": service
            }
        )

        self.add_node(service_node)

        edge = Edge(
            source=port_id,
            target=service_id,
            relation="RUNS"
        )

        self.add_edge(edge)

        return service_node

    # ==================================================
    # FINDING
    # ==================================================

    def add_finding(
        self,
        ip,
        port,
        finding
    ):

        severity = finding.get(
            "severity",
            "UNKNOWN"
        )

        title = finding.get(
            "title",
            "Unknown Finding"
        )

        finding_id = (
            f"{ip}:{port}:"
            f"finding:{title}"
        )

        finding_node = Node(
            node_id=finding_id,
            label=title,
            node_type="FINDING",
            risk=severity,
            metadata={
                "ip": ip,
                "port": port,
                "severity": severity,
                "reason": finding.get(
                    "reason",
                    ""
                )
            }
        )

        self.add_node(finding_node)

        edge = Edge(
            source=f"{ip}:{port}",
            target=finding_id,
            relation="HAS_FINDING",
            risk=severity
        )

        self.add_edge(edge)

        return finding_node

    # ==================================================
    # RISK PATH
    # ==================================================

    def add_risk_path(
        self,
        ip,
        port,
        risk
    ):

        risk_id = (
            f"{ip}:{port}:risk:{risk}"
        )

        risk_node = Node(
            node_id=risk_id,
            label=f"{risk} RISK",
            node_type="RISK",
            risk=risk,
            metadata={
                "ip": ip,
                "port": port
            }
        )

        self.add_node(risk_node)

        edge = Edge(
            source=f"{ip}:{port}",
            target=risk_id,
            relation="LEADS_TO_RISK",
            risk=risk
        )

        self.add_edge(edge)

        return risk_node

    # ==================================================
    # BUILD
    # ==================================================

    def build(
        self,
        ip,
        ports,
        risk="LOW",
        risk_score=0,
        services=None,
        findings=None
    ):
        """
        Build a complete graph for one host.

        Existing calls using:

            build(ip, ports)

        are still supported.
        """

        services = services or {}
        findings = findings or {}

        # --------------------------
        # Host
        # --------------------------

        self.add_host(
            ip,
            risk,
            risk_score
        )

        # --------------------------
        # Ports
        # --------------------------

        for port in ports:

            service = services.get(
                port,
                "UNKNOWN"
            )

            self.add_port(
                ip,
                port,
                service
            )

            # ----------------------
            # Service
            # ----------------------

            if service != "UNKNOWN":

                self.add_service(
                    ip,
                    port,
                    service
                )

            # ----------------------
            # Findings
            # ----------------------

            port_findings = findings.get(
                port,
                []
            )

            for finding in port_findings:

                self.add_finding(
                    ip,
                    port,
                    finding
                )

            # ----------------------
            # Risk
            # ----------------------

            if risk in (
                "MEDIUM",
                "HIGH"
            ):

                self.add_risk_path(
                    ip,
                    port,
                    risk
                )

        return self.nodes, self.edges

    # ==================================================
    # EXPORT
    # ==================================================

    def to_dict(self):

        return {
            "nodes": [
                node.to_dict()
                for node in self.nodes
            ],
            "edges": [
                edge.to_dict()
                for edge in self.edges
            ]
        }

    # ==================================================
    # RESET
    # ==================================================

    def clear(self):

        self.nodes.clear()
        self.edges.clear()

        self._node_ids.clear()
        self._edge_keys.clear()