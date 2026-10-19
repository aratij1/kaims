import pytest
from common.evidence_subject import metric_matches_subject, service_matches

@pytest.mark.parametrize('observed,expected', [('fault-lab','kaiops-fault-lab'),('rs-redis','robot-shop-redis'),('mysql-exporter','kaiops-mysql-exporter')])
def test_explicit_runtime_naming_conventions_match(observed,expected):
 assert service_matches(observed,expected)

@pytest.mark.parametrize('labels', [{'job':'kaiops-api-gateway'},{'service':'payments'},{'job':'kaiops-redis'}])
def test_other_services_cannot_be_relabelled_as_subject(labels):
 assert not metric_matches_subject(labels,'kaiops-mysql-exporter',query='up{job=~"kaiops-.*"} == 0')

def test_platform_redis_does_not_explain_robot_shop_redis():
 assert not service_matches('redis','robot-shop-redis')
 assert not service_matches('kaims-redis','robot-shop-redis')
 assert metric_matches_subject({'job':'rs-redis'},'robot-shop-redis')

def test_probe_and_aggregate_without_subject_are_not_context():
 assert not metric_matches_subject({},'api-gateway',query='vector(1)')
 assert not metric_matches_subject({},'api-gateway',query='sum(up)')
 assert metric_matches_subject({},'api-gateway',query='sum(up{service="api-gateway"})')

def test_explicit_scrape_target_filters_instances():
 target={'job':'mysql','instance':'mysql-exporter:9104'}
 assert metric_matches_subject({'job':'mysql','instance':'mysql-exporter:9104'},'mysql-exporter',target_labels=target)
 assert not metric_matches_subject({'job':'mysql','instance':'other-exporter:9104'},'mysql-exporter',target_labels=target)


def test_same_service_different_operation_is_not_incident_evidence():
    from common.evidence_subject import metric_matches_subject
    target={"operation": "/onboarding/templates", "environment": "prod"}
    assert not metric_matches_subject({"service":"api-gateway","operation":"/applications"},"api-gateway",target_labels=target)
    assert metric_matches_subject({"service":"api-gateway","operation":"/onboarding/templates"},"api-gateway",target_labels=target)
    assert metric_matches_subject({"job":"api-gateway","__name__":"up"},"api-gateway",target_labels=target)
    assert not metric_matches_subject({"service":"api-gateway","operation":"/onboarding/templates","environment":"demo"},"api-gateway",target_labels=target)


def test_disk_evidence_must_match_mount_and_device_not_just_exporter():
    target = {"job": "node-exporter", "instance": "host:9100", "mountpoint": "/mnt/host/d", "device": "D:"}
    assert metric_matches_subject(dict(target), "node-exporter", target_labels=target)
    assert not metric_matches_subject({**target, "mountpoint": "/mnt/host/c"}, "node-exporter", target_labels=target)
    assert not metric_matches_subject({**target, "device": "C:"}, "node-exporter", target_labels=target)
