"""Domain entities for intelligence correlation and entity relationship graphs."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
from app.domain.common.entities import Entity, AggregateRoot, utc_now
from app.domain.correlation.value_objects import NodeType, RelationshipType


@dataclass
class GraphNode(Entity):
    """A node in the correlation graph."""
    id: str
    node_type: NodeType
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge(Entity):
    """A directed edge in the correlation graph."""
    id: str
    source_id: str
    target_id: str
    relationship: RelationshipType
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CorrelatedGraph(AggregateRoot):
    """Aggregated graph representation of investigation reconnaissance."""
    investigation_id: str
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    generated_at: datetime = field(default_factory=utc_now)

    def add_node(self, node: GraphNode) -> None:
        """Add node if not already present."""
        if not any(n.id == node.id for n in self.nodes):
            self.nodes.append(node)

    def add_edge(self, edge: GraphEdge) -> None:
        """Add edge if not already present."""
        if not any(e.id == edge.id for e in self.edges):
            self.edges.append(edge)

