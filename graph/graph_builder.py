"""Graph builder constructing relational models between hosts, ports, services, and findings."""

from typing import List, Tuple, Dict, Any, Optional
from graph.node import Node
from graph.edge import Edge


class GraphBuilder:
    """Builds node and edge topology for the attack graph."""

    def __init__(self):
        self.nodes: List[Node] = []
        self.edges: List[Edge] = []
        self._node_ids: set = set()
        self._edge_keys: set = set()

    def add_node(self, node: Node) -> None:
        if node.node_id not in self._node_ids:
            self.nodes.append(node)
            self._node_ids.add(node.node_id)

    def add_edge(self, edge: Edge) -> None:
        key = (edge.source, edge.target, edge.relation)
        if key not in self._edge_keys:
            self.edges.append(edge)
            self._edge_keys.add(key)

    def add_host(self, ip: str, risk: str = "LOW", risk_score: int = 0) -> Node:
        host = Node(
            node_id=f"host:{ip}",
            label=ip,
            node_type="HOST",
            risk=risk,
            metadata={"ip": ip, "risk_score": risk_score},
        )
        self.add_node(host)
        return host

    def add_port(self, ip: str, port: int, service: str = "UNKNOWN") -> Node:
        host_id = f"host:{ip}"
        port_id = f"{ip}:{port}"

        port_node = Node(
            node_id=port_id,
            label=str(port),
            node_type="PORT",
            metadata={"ip": ip, "port": port, "service": service},
        )
        self.add_node(port_node)

        edge = Edge(
            source=host_id,
            target=port_id,
            relation="EXPOSES",
            metadata={"port": port},
        )
        self.add_edge(edge)
        return port_node

    def add_service(self, ip: str, port: int, service: str) -> Node:
        port_id = f"{ip}:{port}"
        service_id = f"{ip}:{port}:service"

        service_node = Node(
            node_id=service_id,
            label=service,
            node_type="SERVICE",
            metadata={"ip": ip, "port": port, "service": service},
        )
        self.add_node(service_node)

        edge = Edge(source=port_id, target=service_id, relation="RUNS")
        self.add_edge(edge)
        return service_node

    def add_finding(self, ip: str, port: int, finding: Dict[str, Any]) -> Node:
        severity = finding.get("severity", "UNKNOWN")
        title = finding.get("title", "Unknown Finding")
        finding_id = f"{ip}:{port}:finding:{title}"

        finding_node = Node(
            node_id=finding_id,
            label=title,
            node_type="FINDING",
            risk=severity,
            metadata={
                "ip": ip,
                "port": port,
                "severity": severity,
                "reason": finding.get("reason", ""),
            },
        )
        self.add_node(finding_node)

        edge = Edge(
            source=f"{ip}:{port}",
            target=finding_id,
            relation="HAS_FINDING",
            risk=severity,
        )
        self.add_edge(edge)
        return finding_node

    def add_risk_path(self, ip: str, port: int, risk: str) -> Node:
        risk_id = f"{ip}:{port}:risk:{risk}"
        risk_node = Node(
            node_id=risk_id,
            label=f"{risk} RISK",
            node_type="RISK",
            risk=risk,
            metadata={"ip": ip, "port": port},
        )
        self.add_node(risk_node)

        edge = Edge(
            source=f"{ip}:{port}",
            target=risk_id,
            relation="LEADS_TO_RISK",
            risk=risk,
        )
        self.add_edge(edge)
        return risk_node

    def build(
        self,
        ip: str,
        ports: List[int],
        risk: str = "LOW",
        risk_score: int = 0,
        services: Optional[Dict[int, str]] = None,
        findings: Optional[Dict[int, List[Dict[str, Any]]]] = None,
    ) -> Tuple[List[Node], List[Edge]]:
        services = services or {}
        findings = findings or {}

        self.add_host(ip, risk, risk_score)

        for port in ports:
            service = services.get(port, "UNKNOWN")
            self.add_port(ip, port, service)

            if service != "UNKNOWN":
                self.add_service(ip, port, service)

            for finding in findings.get(port, []):
                self.add_finding(ip, port, finding)

            if risk in ("MEDIUM", "HIGH"):
                self.add_risk_path(ip, port, risk)

        return self.nodes, self.edges

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }

    def clear(self) -> None:
        self.nodes.clear()
        self.edges.clear()
        self._node_ids.clear()
        self._edge_keys.clear()
