"""Deterministic parsers for common security telemetry formats."""
from __future__ import annotations
import csv, io, json
from .models import sha256_raw_record
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Any
from .models import EvidenceRecord, Event, Provenance, Claim, EpistemicState
def _time(value: Any, offset: float = 0, timezone_name: str | None = None) -> datetime:
    zone = ZoneInfo(timezone_name) if timezone_name else timezone.utc
    if isinstance(value, datetime): return value if value.tzinfo else value.replace(tzinfo=zone)
    s = str(value or "1970-01-01T00:00:00Z").replace("Z", "+00:00")
    try: d = datetime.fromisoformat(s)
    except ValueError: d = datetime.fromtimestamp(float(value), tz=zone)
    d = d if d.tzinfo else d.replace(tzinfo=zone)
    from datetime import timedelta
    return d + timedelta(seconds=offset)
def _record(raw, source, kind, locator, at, line=None, verbatim=None, config=None):
    config = config or {}
    # Explicit field mappings are applied without mutating the immutable raw payload.
    mapped = dict(raw)
    for canonical, original in (config.get("field_mappings") or {}).items():
        if original in raw: mapped[canonical] = raw[original]
    claims=[]
    for key in ("user", "username", "account"):
        if mapped.get(key) is not None: claims.append(Claim(subject=str(mapped.get("id") or mapped.get("event_id") or locator), predicate="actor", object=str(mapped[key]), epistemic_state=EpistemicState.OBSERVED))
    if mapped.get("src_ip") or mapped.get("source_ip"): claims.append(Claim(subject=locator,predicate="source_ip",object=mapped.get("src_ip",mapped.get("source_ip")),epistemic_state=EpistemicState.OBSERVED))
    offset = float(config.get("known_clock_offset_seconds", 0) or 0); zone = config.get("timezone")
    return EvidenceRecord(raw_record=raw,event=Event(event_type=str(mapped.get("event_type") or mapped.get("event") or mapped.get("action") or kind),occurred_at=_time(at, offset, zone),ts_uncertainty_s=abs(offset),data=mapped),provenance=Provenance(source=source,captured_at=_time(at, 0, zone),locator=locator,collector="traceweave"),claims=tuple(claims),source_id=config.get("source_id") or source,file=source,line=line,verbatim=verbatim or "",raw_line=verbatim or "",raw_sha256=sha256_raw_record(raw))
def parse_auth_jsonl(text, source="auth.jsonl", config=None):
    out=[]
    for n,line in enumerate(text.splitlines(),1):
        if line.strip():
            raw=json.loads(line); out.append(_record(raw,source,"auth",str(raw.get("id",n)),raw.get("timestamp",raw.get("time")),n,line,config))
    return out
def parse_application_audit(text, source="application.audit", config=None):
    out=[]
    for n,line in enumerate(text.splitlines(),1):
        if not line.strip() or line.lstrip().startswith("#"): continue
        try: raw=json.loads(line)
        except json.JSONDecodeError:
            raw={k:v.strip("\"'") for k,v in (t.split("=",1) for t in line.split() if "=" in t)}
            if not raw:
                raise ValueError(f"line {n} is neither JSON nor key=value audit data")
        out.append(_record(raw,source,"application_audit",str(raw.get("id",n)),raw.get("timestamp",raw.get("time")),n,line,config))
    return out
def parse_network_csv(text, source="network.csv", config=None):
    out=[]; lines=text.splitlines(); reader=csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("network CSV must include a header")
    if not {"timestamp", "ts", "time"}.intersection(reader.fieldnames):
        raise ValueError("network CSV must include timestamp, ts, or time column")
    for n,raw in enumerate(reader,2):
        verbatim=lines[n-1] if n-1 < len(lines) else ",".join(str(value or "") for value in raw.values())
        out.append(_record(dict(raw),source,"network",str(raw.get("id",n)),raw.get("timestamp",raw.get("ts",raw.get("time"))),n,verbatim,config))
    return out
def parse_records(text, kind, source="input"):
    return {"auth":parse_auth_jsonl,"application":parse_application_audit,"audit":parse_application_audit,"network":parse_network_csv}[kind](text,source)
