import json
from common.metric_queries import filesystem_evidence_query


def test_filesystem_question_queries_named_metrics_for_the_exact_mount():
    query = filesystem_evidence_query({"job": "node-exporter", "instance": "host:9100", "mountpoint": "/mnt/host/d", "device": 'D:"'}, question="Confirm filesystem and inode usage")
    assert "files_free" in query and "readonly" in query
    assert 'mountpoint="/mnt/host/d"' in query
    expected_device = json.dumps('D:"')
    assert f'device={expected_device}' in query
    assert 'job="node-exporter"' in query


def test_missing_target_never_queries_all_hosts():
    assert filesystem_evidence_query({}, question="filesystem usage") is None
    assert filesystem_evidence_query({"job": "api"}, question="request latency") is None

def test_registered_consumer_signal_requires_exact_operator_scope():
    from common.metric_queries import registered_signal_metric
    telemetry = {'signal_metric_bindings': {'DeadLetters': {
        'service': 'rabbitmq', 'tenant_id': 'tenant-a', 'environment': 'prod',
        'metric_name': 'kaiops_dead_letter_events_total', 'labels': {'provider': 'rabbitmq'}}}}
    args = {'alert_name': 'DeadLetters', 'service': 'rabbitmq', 'tenant_id': 'tenant-a', 'environment': 'prod'}
    query, labels = registered_signal_metric(telemetry, args)
    assert labels == {'__name__': 'kaiops_dead_letter_events_total', 'provider': 'rabbitmq'}
    assert 'provider="rabbitmq"' in query
    for field in args:
        assert registered_signal_metric(telemetry, {**args, field: 'other'}) is None


def test_dead_letter_counter_is_attributed_to_delivery_path_without_changing_emitter():
    from common.evidence_subject import metric_matches_subject
    labels = {'__name__': 'kaiops_dead_letter_events_total', 'provider': 'rabbitmq',
              'job': 'kaiops-resolution-agent', 'queue': 'context-events', 'reason': 'handler_failed'}
    assert metric_matches_subject(labels, 'rabbitmq')
    assert labels['job'] == 'kaiops-resolution-agent'
    assert not metric_matches_subject({**labels, 'provider': 'kafka'}, 'rabbitmq')
    assert not metric_matches_subject({**labels, '__name__': 'up'}, 'rabbitmq')
    assert not metric_matches_subject(labels, 'robot-shop-rabbitmq')
