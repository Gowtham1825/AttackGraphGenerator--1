
import os
import shutil
from datetime import datetime

from pyvis.network import Network


class GraphVisualizer:
    """
    Generates an interactive security attack graph.

    Graph structure:

        HOST
          |
          v
        PORT
          |
          v
       FINDING
          |
          v
      RISK PATH
    """

    # ==================================================
    # INITIALIZATION
    # ==================================================

    def __init__(self):

        self.net = Network(
            height="850px",
            width="100%",
            bgcolor="#111827",
            font_color="white",
            directed=True
        )

        # Track nodes and edges to avoid duplicates
        self.nodes = set()
        self.edges = set()

        self._configure_graph()

    # ==================================================
    # GRAPH CONFIGURATION
    # ==================================================

    def _configure_graph(self):

        self.net.set_options("""
        {
            "nodes": {
                "font": {
                    "size": 16,
                    "face": "Arial"
                },
                "borderWidth": 2,
                "shadow": true
            },

            "edges": {
                "arrows": {
                    "to": {
                        "enabled": true,
                        "scaleFactor": 0.7
                    }
                },

                "smooth": {
                    "enabled": true,
                    "type": "dynamic"
                },

                "width": 2,
                "color": {
                    "inherit": false
                }
            },

            "physics": {
                "enabled": true,

                "barnesHut": {
                    "gravitationalConstant": -3500,
                    "centralGravity": 0.2,
                    "springLength": 180,
                    "springConstant": 0.04,
                    "damping": 0.09
                },

                "stabilization": {
                    "enabled": true,
                    "iterations": 1000,
                    "fit": true
                }
            },

            "interaction": {
                "hover": true,
                "navigationButtons": true,
                "keyboard": true,
                "dragNodes": true,
                "zoomView": true,
                "selectConnectedEdges": true
            }
        }
        """)

    # ==================================================
    # INTERNAL HELPERS
    # ==================================================

    def _add_node(self, node_id, **kwargs):

        if node_id in self.nodes:
            return

        self.net.add_node(
            node_id,
            **kwargs
        )

        self.nodes.add(node_id)

    def _add_edge(
        self,
        source,
        target,
        relation="",
        color=None
    ):

        edge_key = (
            source,
            target,
            relation
        )

        if edge_key in self.edges:
            return

        edge_data = {
            "arrows": "to"
        }

        if relation:
            edge_data["label"] = relation

        if color:
            edge_data["color"] = color

        self.net.add_edge(
            source,
            target,
            **edge_data
        )

        self.edges.add(edge_key)

    # ==================================================
    # HOST NODE
    # ==================================================

    def add_host(
        self,
        ip,
        risk,
        score
    ):

        color = {
            "LOW": "#22C55E",
            "MEDIUM": "#F59E0B",
            "HIGH": "#EF4444",
            "CRITICAL": "#991B1B"
        }.get(
            risk,
            "#3B82F6"
        )

        self._add_node(
            ip,

            label=(
                f"HOST\n"
                f"{ip}\n"
                f"Risk: {risk}\n"
                f"Score: {score}"
            ),

            title=(
                f"<b>Network Host</b><br><br>"
                f"IP Address: {ip}<br>"
                f"Risk Level: {risk}<br>"
                f"Risk Score: {score}"
            ),

            color=color,
            shape="box"
        )

    # ==================================================
    # PORT / SERVICE NODE
    # ==================================================

    def add_port(
        self,
        ip,
        port,
        service
    ):

        node_id = f"{ip}:{port}"

        self._add_node(
            node_id,

            label=(
                f"{service}\n"
                f"Port: {port}"
            ),

            title=(
                f"<b>Exposed Service</b><br><br>"
                f"Host: {ip}<br>"
                f"Port: {port}<br>"
                f"Service: {service}"
            ),

            color="#38BDF8",
            shape="ellipse"
        )

        self._add_edge(
            ip,
            node_id,
            relation="EXPOSES"
        )

    # ==================================================
    # SECURITY FINDING
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

        reason = finding.get(
            "reason",
            "No reason provided."
        )

        finding_id = (
            f"finding:"
            f"{ip}:"
            f"{port}:"
            f"{title}"
        )

        color = {
            "LOW": "#86EFAC",
            "MEDIUM": "#F59E0B",
            "HIGH": "#EF4444",
            "CRITICAL": "#991B1B",
            "UNKNOWN": "#9CA3AF"
        }.get(
            severity,
            "#9CA3AF"
        )

        self._add_node(
            finding_id,

            label=(
                f"{severity}\n"
                f"{title}"
            ),

            title=(
                f"<b>Security Finding</b><br><br>"
                f"Severity: {severity}<br>"
                f"Finding: {title}<br><br>"
                f"<b>Reason</b><br>"
                f"{reason}"
            ),

            shape="diamond",
            color=color
        )

        self._add_edge(
            f"{ip}:{port}",
            finding_id,
            relation="HAS FINDING",
            color=color
        )

    # ==================================================
    # RISK PATH
    # ==================================================

    def add_risk_path(
        self,
        ip,
        port,
        risk
    ):

        path_id = (
            f"risk:"
            f"{ip}:"
            f"{port}:"
            f"{risk}"
        )

        color = {
            "MEDIUM": "#F59E0B",
            "HIGH": "#EF4444",
            "CRITICAL": "#991B1B"
        }.get(
            risk,
            "#9CA3AF"
        )

        self._add_node(
            path_id,

            label=(
                f"RISK PATH\n"
                f"{risk}"
            ),

            title=(
                f"<b>Potential Risk Path</b><br><br>"
                f"Host: {ip}<br>"
                f"Port: {port}<br>"
                f"Risk Level: {risk}"
            ),

            shape="star",
            color=color
        )

        self._add_edge(
            f"{ip}:{port}",
            path_id,
            relation="LEADS TO",
            color=color
        )

    # ==================================================
    # SAVE GRAPH
    # ==================================================

    def save(
        self,
        filename="reports/graphs/attack_graph.html"
    ):

        # Create graph directory
        graph_dir = os.path.dirname(filename) or "."

        os.makedirs(
            graph_dir,
            exist_ok=True
        )

        # ==================================================
        # BACKUP EXISTING GRAPH
        # ==================================================

        if os.path.exists(filename):

            timestamp = datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )

            backup_filename = os.path.join(
                graph_dir,
                f"attack_graph_{timestamp}.html"
            )

            shutil.copy2(
                filename,
                backup_filename
            )

            print(
                f"[+] Previous graph backed up: "
                f"{backup_filename}"
            )

        # ==================================================
        # SAVE CURRENT GRAPH
        # ==================================================

        self.net.write_html(
            filename,
            open_browser=False,
            notebook=False
        )

        print(
            "\n[+] Attack graph saved successfully"
        )

        print(
            f"[+] Graph: {filename}"
        )

        print(
            f"[+] Nodes: {len(self.nodes)}"
        )

        print(
            f"[+] Edges: {len(self.edges)}"
        )
