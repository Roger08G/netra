import json

from netra.render import build_html


def test_report_escapes_embedded_script_terminator(tmp_path):
    artifact = {
        "schema_version": "1.0.0",
        "run": {"id": "run-test", "scope": ["192.168.1.0/24"]},
        "coverage": {"statement": "test"},
        "assets": [{"id": "host", "names": ["</script><script>alert(1)</script>"]}],
        "relationships": [],
    }
    destination = tmp_path / "report.html"
    build_html(artifact, destination)
    text = destination.read_text(encoding="utf-8")
    assert "</script><script>alert(1)</script>" not in text
    assert "<\\/script>" in text
    assert json.dumps(artifact, ensure_ascii=False).replace("</", "<\\/") in text


def test_report_placeholders_inside_data_do_not_modify_template(tmp_path):
    artifact = {
        "schema_version": "1.0.0",
        "run": {"id": "__NETRA_DATA__", "scope": []},
        "coverage": {"statement": "__NETRA_TITLE__"},
        "assets": [],
        "relationships": [],
    }
    destination = tmp_path / "report.html"
    build_html(artifact, destination)
    text = destination.read_text(encoding="utf-8")
    assert "<title>Netra · __NETRA_DATA__</title>" in text
    assert '"statement": "__NETRA_TITLE__"' in text
