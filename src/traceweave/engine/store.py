"""Append-only in-memory evidence hash chain."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
from .models import EvidenceRecord

class EvidenceChainTamperedError(ValueError):
    """Raised when a chain entry no longer matches its signed link."""

@dataclass
class _Entry:
    record: EvidenceRecord
    previous_hash: str
    chain_hash: str

class HashChainEvidenceStore:
    """An append-only store whose links make post-write mutation detectable."""
    def __init__(self) -> None:
        self._entries: list[_Entry] = []
    @property
    def records(self) -> tuple[EvidenceRecord, ...]:
        return tuple(entry.record for entry in self._entries)
    @property
    def entries(self) -> tuple[_Entry, ...]:
        return tuple(self._entries)
    def append(self, record: EvidenceRecord) -> str:
        previous_hash = self._entries[-1].chain_hash if self._entries else "0" * 64
        chain_hash = self._link_hash(record, previous_hash)
        self._entries.append(_Entry(record, previous_hash, chain_hash))
        return chain_hash
    def verify(self) -> bool:
        previous_hash = "0" * 64
        for index, entry in enumerate(self._entries):
            if entry.previous_hash != previous_hash:
                raise EvidenceChainTamperedError(f"entry {index} has an invalid predecessor")
            expected = self._link_hash(entry.record, previous_hash)
            if entry.chain_hash != expected:
                raise EvidenceChainTamperedError(f"entry {index} has been tampered with")
            previous_hash = entry.chain_hash
        return True
    @staticmethod
    def link_hash(previous_hash: str, raw_record: object) -> str:
        """Return the canonical persisted hash-chain link."""
        from .models import canonical_json
        return hashlib.sha256(f"{previous_hash}:{canonical_json(raw_record)}".encode("utf-8")).hexdigest()

    @classmethod
    def _link_hash(cls, record: EvidenceRecord, previous_hash: str) -> str:
        return cls.link_hash(previous_hash, record.raw_record)
