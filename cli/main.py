"""Analyze local files and emit TraceWeave reports."""
from __future__ import annotations
import json
from pathlib import Path
import typer
from traceweave.engine import analyze as engine_analyze, html_report, parse_auth_jsonl, parse_application_audit, parse_network_csv

def _build_case(files: list[tuple[str, bytes]]) -> dict:
    """Build a report without importing or booting the FastAPI application."""
    parsers = {"auth": parse_auth_jsonl, "application_audit": parse_application_audit, "network": parse_network_csv}
    records = []
    for name, data in files:
        text = data.decode("utf-8", errors="replace")
        lower = name.lower()
        kind = "network" if lower.endswith((".csv", ".conn", ".network")) else "auth" if lower.endswith((".jsonl", ".auth", ".json")) else "application_audit"
        records.extend(parsers[kind](text, name))
    result = engine_analyze(records, expected_sources={name for name, _ in files})
    return {"records": [record.model_dump(mode="json") for record in result.records], "claims": [claim.model_dump(mode="json") for claim in result.claims], "timeline": [record.event.model_dump(mode="json") | {"record_id": record.id, "source": record.file or record.source_id} for record in result.records], "contradictions": result.contradictions, "gaps": result.gaps, "graph": result.graph.as_dict(), "chain_valid": result.chain.verify(), "confidence_breakdown": result.confidence_breakdown}
app = typer.Typer(help="Analyze evidence files with TraceWeave.")
@app.callback()
def root() -> None:
    """TraceWeave local analysis commands."""
    pass
@app.command()
def analyze(input_dir: Path = typer.Argument(..., exists=True, file_okay=False), output: Path = typer.Option(Path("traceweave-report.json"), "--output", "-o"), format: str = typer.Option("json", "--format")) -> None:
    """Analyze every regular file in INPUT_DIR."""
    supported = (".jsonl", ".auth", ".audit", ".audit.log", ".app.log", ".csv", ".conn", ".network")
    files = [(p.name, p.read_bytes()) for p in sorted(input_dir.iterdir()) if p.is_file() and p.name.lower().endswith(supported)]
    if not files:
        raise typer.BadParameter("INPUT_DIR contains no supported evidence files")
    case = _build_case(files); output.parent.mkdir(parents=True, exist_ok=True)
    if format == "json": output.write_text(json.dumps(case, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    elif format == "html":
        output.write_text(html_report(case), encoding="utf-8")
    else: raise typer.BadParameter("format must be json or html")
    typer.echo(str(output))
if __name__ == "__main__": app()
