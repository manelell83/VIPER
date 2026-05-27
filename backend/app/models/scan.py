import json
from datetime import datetime
from uuid import uuid4
from sqlalchemy import Column, String, DateTime, Text, ForeignKey, Integer
from sqlalchemy.orm import relationship
from app.core.database import Base


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    type = Column(String, nullable=False)          # "network" | "domain"
    target = Column(String, nullable=False)         # subnet CIDR or domain/IP
    interface = Column(String, nullable=True)       # interface name for network scans
    status = Column(String, default="pending")      # pending|running|completed|failed
    error = Column(Text, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    hosts = relationship("Host", back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "target": self.target,
            "interface": self.interface,
            "status": self.status,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "hosts_count": len(self.hosts),
        }


class Host(Base):
    __tablename__ = "hosts"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    scan_id = Column(String, ForeignKey("scan_sessions.id"), nullable=False)
    ip = Column(String, nullable=False)
    mac = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    os = Column(String, nullable=True)
    os_accuracy = Column(Integer, nullable=True)
    status = Column(String, default="up")
    ports_json = Column(Text, default="[]")
    discovered_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanSession", back_populates="hosts")
    vulnerabilities = relationship(
        "Vulnerability", back_populates="host", cascade="all, delete-orphan"
    )

    @property
    def ports(self):
        try:
            return json.loads(self.ports_json or "[]")
        except Exception:
            return []

    @ports.setter
    def ports(self, value):
        self.ports_json = json.dumps(value)

    @property
    def open_ports_count(self):
        return sum(1 for p in self.ports if p.get("state") == "open")

    @property
    def vuln_count(self):
        return len(self.vulnerabilities) if self.vulnerabilities else 0

    def max_severity(self) -> str:
        return self._max_severity()

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "os": self.os,
            "os_accuracy": self.os_accuracy,
            "status": self.status,
            "ports": self.ports,
            "open_ports_count": self.open_ports_count,
            "vuln_count": self.vuln_count,
            "max_severity": self.max_severity(),
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }

    def _max_severity(self) -> str:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
        sev_set = {v.severity for v in (self.vulnerabilities or [])}
        for s in order:
            if s in sev_set:
                return s
        return "NONE"
