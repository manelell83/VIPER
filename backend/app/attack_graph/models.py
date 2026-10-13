import json
from uuid import uuid4

from sqlalchemy import (
    Column, String, Float, Integer, Text, DateTime, ForeignKey, Boolean
)
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.core.timeutil import iso_utc, utcnow


class AttackGraph(Base):
    __tablename__ = "attack_graphs"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    scan_id = Column(String, ForeignKey("scan_sessions.id", ondelete="CASCADE"), nullable=False, unique=True)
    generated_at = Column(DateTime, default=utcnow)
    node_count = Column(Integer, default=0)
    edge_count = Column(Integer, default=0)
    path_count = Column(Integer, default=0)
    entry_point_count = Column(Integer, default=0)
    network_risk_level = Column(String, default="NONE")
    summary_json = Column(Text, default="{}")

    nodes = relationship("AttackNode", back_populates="graph", cascade="all, delete-orphan")
    edges = relationship("AttackEdge", back_populates="graph", cascade="all, delete-orphan")
    paths = relationship("AttackPath", back_populates="graph", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "generated_at": iso_utc(self.generated_at),
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "path_count": self.path_count,
            "entry_point_count": self.entry_point_count,
            "network_risk_level": self.network_risk_level,
            "summary": json.loads(self.summary_json or "{}"),
        }


class AttackNode(Base):
    __tablename__ = "attack_nodes"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    graph_id = Column(String, ForeignKey("attack_graphs.id", ondelete="CASCADE"), nullable=False)
    host_id = Column(String, ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    node_type = Column(String, nullable=False)  # ATTACKER | ENTRY | PIVOT | TARGET | INTERNAL
    label = Column(String, nullable=False)
    ip = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    is_entry_point = Column(Boolean, default=False)
    is_critical = Column(Boolean, default=False)
    metadata_json = Column(Text, default="{}")

    graph = relationship("AttackGraph", back_populates="nodes")
    outgoing_edges = relationship(
        "AttackEdge",
        foreign_keys="AttackEdge.source_node_id",
        back_populates="source_node",
        cascade="all, delete-orphan",
    )
    incoming_edges = relationship(
        "AttackEdge",
        foreign_keys="AttackEdge.target_node_id",
        back_populates="target_node",
        cascade="all, delete-orphan",
    )

    def to_dict(self):
        return {
            "id": self.id,
            "graph_id": self.graph_id,
            "host_id": self.host_id,
            "node_type": self.node_type,
            "label": self.label,
            "ip": self.ip,
            "risk_score": self.risk_score,
            "is_entry_point": self.is_entry_point,
            "is_critical": self.is_critical,
            "metadata": json.loads(self.metadata_json or "{}"),
        }


class AttackEdge(Base):
    __tablename__ = "attack_edges"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    graph_id = Column(String, ForeignKey("attack_graphs.id", ondelete="CASCADE"), nullable=False)
    source_node_id = Column(String, ForeignKey("attack_nodes.id", ondelete="CASCADE"), nullable=False)
    target_node_id = Column(String, ForeignKey("attack_nodes.id", ondelete="CASCADE"), nullable=False)
    attack_type = Column(String, nullable=False)  # REMOTE_ACCESS | LATERAL_MOVEMENT | ...
    attack_vector = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    service = Column(String, nullable=True)
    cvss = Column(Float, default=0.0)
    cve_ids_json = Column(Text, default="[]")
    score = Column(Float, default=0.0)  # 0-100, higher = more dangerous
    description = Column(Text, nullable=True)
    # Evidence-based 3-component breakdown (see scoring.py)
    reachability = Column(Float, nullable=True)
    exploitability = Column(Float, nullable=True)
    impact = Column(Float, nullable=True)
    factors_json = Column(Text, default="[]")
    mitre_json = Column(Text, default="[]")
    justification = Column(Text, nullable=True)

    graph = relationship("AttackGraph", back_populates="edges")
    source_node = relationship(
        "AttackNode",
        foreign_keys=[source_node_id],
        back_populates="outgoing_edges",
    )
    target_node = relationship(
        "AttackNode",
        foreign_keys=[target_node_id],
        back_populates="incoming_edges",
    )

    def to_dict(self):
        return {
            "id": self.id,
            "source": self.source_node_id,
            "target": self.target_node_id,
            "attack_type": self.attack_type,
            "attack_vector": self.attack_vector,
            "port": self.port,
            "service": self.service,
            "cvss": self.cvss,
            "cve_ids": json.loads(self.cve_ids_json or "[]"),
            "score": self.score,
            "description": self.description,
            "reachability": self.reachability,
            "exploitability": self.exploitability,
            "impact": self.impact,
            "factors": json.loads(self.factors_json or "[]"),
            "mitre": json.loads(self.mitre_json or "[]"),
            "justification": self.justification,
        }


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    graph_id = Column(String, ForeignKey("attack_graphs.id", ondelete="CASCADE"), nullable=False)
    path_node_ids_json = Column(Text, default="[]")
    path_ips_json = Column(Text, default="[]")
    attack_vectors_json = Column(Text, default="[]")
    total_score = Column(Float, default=0.0)
    hop_count = Column(Integer, default=0)
    entry_ip = Column(String, nullable=True)
    target_ip = Column(String, nullable=True)
    severity = Column(String, default="LOW")
    cve_ids_json = Column(Text, default="[]")
    # Evidence-based 3-component breakdown + justification + MITRE (see scoring.py)
    reachability_score = Column(Float, nullable=True)
    exploitability_score = Column(Float, nullable=True)
    impact_score = Column(Float, nullable=True)
    factors_json = Column(Text, default="[]")
    mitre_json = Column(Text, default="[]")
    justification = Column(Text, nullable=True)
    hops_json = Column(Text, default="[]")

    graph = relationship("AttackGraph", back_populates="paths")

    def to_dict(self):
        return {
            "id": self.id,
            "graph_id": self.graph_id,
            "path_ips": json.loads(self.path_ips_json or "[]"),
            "path_node_ids": json.loads(self.path_node_ids_json or "[]"),
            "attack_vectors": json.loads(self.attack_vectors_json or "[]"),
            "total_score": self.total_score,
            "hop_count": self.hop_count,
            "entry_ip": self.entry_ip,
            "target_ip": self.target_ip,
            "severity": self.severity,
            "cve_ids": json.loads(self.cve_ids_json or "[]"),
            "reachability_score": self.reachability_score,
            "exploitability_score": self.exploitability_score,
            "impact_score": self.impact_score,
            "factors": json.loads(self.factors_json or "[]"),
            "mitre": json.loads(self.mitre_json or "[]"),
            "justification": self.justification,
            "hops": json.loads(self.hops_json or "[]"),
        }
