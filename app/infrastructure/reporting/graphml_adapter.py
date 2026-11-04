"""GraphML export adapter."""

from app.application.common.interfaces.reporting import IGraphExporterPort
from app.domain.correlation.entities import CorrelatedGraph
from app.services.reporting.graphml_generator import GraphMLExporter


class GraphMLExportAdapter(IGraphExporterPort):
    """Adapts GraphMLExporter to IGraphExporterPort."""

    def __init__(self, exporter: GraphMLExporter = None):
        self.exporter = exporter or GraphMLExporter()

    def export_graphml(self, graph: CorrelatedGraph) -> str:
        # Convert domain graph to exporter input format
        nodes = [{"id": n.id, "label": n.label, "type": n.node_type.value} for n in graph.nodes]
        edges = [{"source": e.source_id, "target": e.target_id, "relationship": e.relationship.value} for e in graph.edges]
        return self.exporter.export(nodes=nodes, edges=edges)

