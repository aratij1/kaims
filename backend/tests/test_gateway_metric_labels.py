from types import SimpleNamespace

from starlette.requests import Request

from api_gateway.metric_labels import gateway_metric_operation


def test_changing_incident_ids_and_queries_does_not_grow_metric_cardinality():
    labels = set()
    for number in range(1000):
        request = Request({"type": "http", "path": f"/incidents/{number}",
                           "query_string": f"tenant_id=tenant-{number}".encode(),
                           "route": SimpleNamespace(path="/incidents/{incident_id}")})
        labels.add(gateway_metric_operation(request))
    assert labels == {"/incidents/{incident_id}"}


def test_unmatched_paths_share_one_metric_label():
    assert gateway_metric_operation(Request({"type": "http", "path": "/random-id"})) == "unmatched"
