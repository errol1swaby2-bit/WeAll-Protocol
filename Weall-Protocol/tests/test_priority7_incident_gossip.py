def test_gossip_roundtrip():
    from weall.runtime.operator_incident_gossip import (
        deserialize_incident_report,
        serialize_incident_report,
    )

    report = {"summary": {"severity": "ok"}, "report_hash": "abc"}
    s = serialize_incident_report(report)
    r = deserialize_incident_report(s)

    assert r["summary"]["severity"] == "ok"
    assert r["report_hash"] == "abc"
