"""CLI-independent deterministic TraceWeave analysis pipeline."""
from dataclasses import dataclass
from typing import Any
from .models import Claim, EpistemicState
from .store import HashChainEvidenceStore
from .graph import EvidenceGraph

@dataclass
class AnalysisResult:
    records: tuple; claims: tuple; contradictions: list; gaps: list; graph: EvidenceGraph; chain: HashChainEvidenceStore; confidence_breakdown: dict
    def as_dict(self):
        return {"records":[r.model_dump(mode="json") for r in self.records],"claims":[c.model_dump(mode="json") for c in self.claims],"contradictions":self.contradictions,"gaps":self.gaps,"graph":self.graph.as_dict(),"chain_valid":self.chain.verify(),"confidence_breakdown":self.confidence_breakdown}

def analyze(records, rules: list[dict[str,Any]]|None=None, expected_sources: set[str]|None=None):
    ordered=tuple(sorted(records,key=lambda r:(r.event.occurred_at,r.id))); chain=HashChainEvidenceStore(); graph=EvidenceGraph(); claims=[]
    for r in ordered:
        chain_hash = chain.append(r)
        # Keep chain metadata on the immutable result object for persistence/API.
        r.chain_hash = chain_hash
        graph.add_record(r)
        claims.extend(r.claims)
    contradictions=[]; by_actor={}
    for r in ordered:
        delta=abs((r.provenance.captured_at-r.event.occurred_at).total_seconds())
        if delta > 86400: contradictions.append({"type":"clock_skew","evidence_id":r.id,"seconds":delta,"provenance":[r.id]})
        for c in r.claims:
            if c.predicate in ("actor","user","identity"): by_actor.setdefault(c.subject,set()).add(str(c.object))
    for s,v in sorted(by_actor.items()):
        if len(v)>1:
            ids=[r.id for r in ordered if any(c.subject==s for c in r.claims)]
            contradictions.append({"type":"identity_conflict","subject":s,"values":sorted(v),"provenance":sorted(ids)})
    gaps=[{"type":"coverage_gap","source":s,"provenance":[]} for s in sorted((expected_sources or set())-{r.provenance.source for r in ordered})]
    for rule in rules or []:
        matching=[r for r in ordered if not rule.get("event_type") or r.event.event_type==rule["event_type"]]
        if matching and rule.get("predicate"):
            r=matching[0]; claims.append(Claim(subject=r.id,predicate=rule["predicate"],object=rule.get("object",True),epistemic_state=EpistemicState.INFERRED,confidence={"score":float(rule.get("confidence",.5)),"factors":{"source_reliability":.8,"temporal_consistency":.8,"entity_linkage":.8}},limitations=["Rule-derived inference"],rule=str(rule.get("id","rule"))))
            graph.add_claim(claims[-1], r.id)
    breakdown={str(rule.get("id","rule")): {"source_reliability":.8,"temporal_consistency":.8,"entity_linkage":.8,"score":float(rule.get("confidence",.5))} for rule in (rules or [])}
    return AnalysisResult(ordered,tuple(claims),contradictions,gaps,graph,chain,breakdown)
