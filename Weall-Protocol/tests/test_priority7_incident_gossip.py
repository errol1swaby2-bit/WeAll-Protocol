from weall.runtime.operator_incident_diff import diff_operator_incident_reports
from weall.runtime.operator_incident_diff import diff_operator_incident_reports as diff
from weall.runtime.operator_incident_diff import diff_operator_incident_reports

def test_gossip_roundtrip():
    from weall.runtime.operator_incident_gossip import serialize_incident_report, deserialize_incident_report

    report = {"summary": {"severity": "ok"}, "report_hash": "abc"}
    s = serialize_incident_report(report)
    r = deserialize_incident_report(s)

    assert r["summary"]["severity"] == "ok"
    assert r["report_hash"] == "abc"
