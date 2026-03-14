from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json

@dataclass
class AnomalyAlert:
    anomaly_type: str
    severity: str
    client_ip: str
    detail: str
    evidence: dict
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_json(self) -> str:
        d = asdict(self)
        d["detected_at"] = self.detected_at.isoformat()
        return json.dumps(d)