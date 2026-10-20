from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app


def test_upload_and_provenance_round_trip(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path))
    files = [
        ("files", (name, (Path("datasets") / name).read_bytes(), "text/plain"))
        for name in ("case1_auth.jsonl", "case1_application.audit", "case1_network.csv")
    ]
    created = client.post("/cases", files=files)
    assert created.status_code == 201
    case_id = created.json()["id"]

    claims = client.get(f"/cases/{case_id}/claims")
    assert claims.status_code == 200
    assert claims.json()
    claim_id = claims.json()[0]["claim_id"]
    provenance = client.get(f"/claims/{claim_id}/provenance")
    assert provenance.status_code == 200
    assert provenance.json()["provenance"]

    report = client.get(f"/cases/{case_id}/report?format=html")
    assert report.status_code == 200
    assert "TraceWeave" in report.text


def test_local_web_origin_is_allowed(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path))
    response = client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"

def test_identical_upload_has_byte_identical_json_report(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path))
    files = [("files", (name, (Path("datasets") / name).read_bytes(), "text/plain")) for name in ("case1_auth.jsonl", "case1_application.audit", "case1_network.csv")]
    first = client.post("/cases", files=files).json()
    second = client.post("/cases", files=files).json()
    assert first["id"] == second["id"]
    left = client.get(f"/cases/{first['id']}/report?format=json").content
    right = client.get(f"/cases/{second['id']}/report?format=json").content
    assert left == right


def test_duplicate_filenames_are_rejected(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path))
    files = [("files", ("events.jsonl", b'{"id":"1","timestamp":"2026-01-01T00:00:00Z"}\n', "application/jsonl")), ("files", ("events.jsonl", b'{"id":"2","timestamp":"2026-01-01T00:00:00Z"}\n', "application/jsonl"))]
    response = client.post("/cases", files=files)
    assert response.status_code == 400

def test_api_chain_matches_engine_and_config_changes_case_identity(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path))
    content = b'{"id":"one","timestamp":"2026-01-01T00:00:00Z"}\n'
    first = client.post("/cases", files={"files": ("events.jsonl", content, "application/jsonl")}, data={"config": "{}"}).json()
    second = client.post("/cases", files={"files": ("events.jsonl", content, "application/jsonl")}, data={"config": '{"events.jsonl":{"source_id":"other"}}'}).json()
    assert first["id"] != second["id"]
    manifest = client.get(f"/cases/{first['id']}/manifest").json()
    assert manifest["chain_valid"] is True
