-- Add missing runbooks for services that generate incidents but had no playbook,
-- causing the resolution gate to stay BLOCKED even when RCA completed.
-- Services covered: kaiops-fault-lab-service, checkout, checkout-api, payments, payments-api

INSERT INTO runbooks (runbook_id, tenant_id, slug, owner, service, alert_family)
VALUES
  ('b1000000-0000-4000-8000-000000000001', 'global', 'kaiops-fault-lab-playbook',         'kaiops-platform-sre', 'kaiops-fault-lab-service', 'availability'),
  ('b1000000-0000-4000-8000-000000000002', 'global', 'checkout-service-down-playbook',     'kaiops-platform-sre', 'checkout',                  'availability'),
  ('b1000000-0000-4000-8000-000000000003', 'global', 'checkout-api-down-playbook',         'kaiops-platform-sre', 'checkout-api',              'availability'),
  ('b1000000-0000-4000-8000-000000000004', 'global', 'payments-latency-playbook',          'kaiops-platform-sre', 'payments',                  'latency'),
  ('b1000000-0000-4000-8000-000000000005', 'global', 'payments-api-down-playbook',         'kaiops-platform-sre', 'payments-api',              'availability'),
  ('b1000000-0000-4000-8000-000000000006', 'global', 'robot-shop-cart-playbook',           'kaiops-platform-sre', 'robot-shop-cart',           'availability'),
  ('b1000000-0000-4000-8000-000000000007', 'global', 'robot-shop-rabbitmq-playbook',       'kaiops-platform-sre', 'robot-shop-rabbitmq',       'availability'),
  ('b1000000-0000-4000-8000-000000000008', 'global', 'robot-shop-shipping-playbook',       'kaiops-platform-sre', 'robot-shop-shipping',       'availability')
ON DUPLICATE KEY UPDATE
  runbook_id = VALUES(runbook_id), slug = VALUES(slug), owner = VALUES(owner),
  service = VALUES(service), alert_family = VALUES(alert_family);

INSERT INTO runbook_versions (
  runbook_id, tenant_id, version, issue_signature, approval_status, owner,
  risk_level, required_approval, content, success_count, failure_count,
  approved_by, approved_at, last_validated_at, created_at
)
VALUES
  ('b1000000-0000-4000-8000-000000000001', 'global', 1, SHA2('kaiops-fault-lab-playbook', 256),
   'approved', 'kaiops-platform-sre', 'high', 'mandatory',
   JSON_OBJECT('slug','kaiops-fault-lab-playbook','status','approved',
     'description','Restart the kaiops-fault-lab-service container via docker-compose executor',
     'recommended_action','Restart service container',
     'steps',JSON_ARRAY('Verify fault-lab:8080 is unreachable via Prometheus','Check container exit code','Restart container via docker-compose executor','Confirm health endpoint responds within 60s'),
     'rollback','Stop restart attempt, escalate to on-call engineer',
     'approval_expires_at','2027-10-22T00:00:00Z','source','backend/database/migrations/20261022_missing_service_runbooks.sql'),
   0, 0, 'release-owner', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000'),

  ('b1000000-0000-4000-8000-000000000002', 'global', 1, SHA2('checkout-service-down-playbook', 256),
   'approved', 'kaiops-platform-sre', 'high', 'mandatory',
   JSON_OBJECT('slug','checkout-service-down-playbook','status','approved',
     'description','Restart the checkout service pod or container',
     'recommended_action','Restart checkout service',
     'steps',JSON_ARRAY('Confirm checkout HTTP 500 or unreachable','Check pod crash logs','Restart pod via kubernetes executor or docker-compose','Verify checkout endpoint returns 200'),
     'rollback','Rollback to previous checkout image tag',
     'approval_expires_at','2027-10-22T00:00:00Z','source','backend/database/migrations/20261022_missing_service_runbooks.sql'),
   0, 0, 'release-owner', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000'),

  ('b1000000-0000-4000-8000-000000000003', 'global', 1, SHA2('checkout-api-down-playbook', 256),
   'approved', 'kaiops-platform-sre', 'high', 'mandatory',
   JSON_OBJECT('slug','checkout-api-down-playbook','status','approved',
     'description','Restart the checkout-api service',
     'recommended_action','Restart checkout-api service',
     'steps',JSON_ARRAY('Confirm checkout-api is unreachable','Check container logs for OOM or crash','Restart container','Verify health endpoint'),
     'rollback','Rollback to last stable checkout-api image',
     'approval_expires_at','2027-10-22T00:00:00Z','source','backend/database/migrations/20261022_missing_service_runbooks.sql'),
   0, 0, 'release-owner', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000'),

  ('b1000000-0000-4000-8000-000000000004', 'global', 1, SHA2('payments-latency-playbook', 256),
   'approved', 'kaiops-platform-sre', 'high', 'mandatory',
   JSON_OBJECT('slug','payments-latency-playbook','status','approved',
     'description','Roll back the payments deployment if latency regression is caused by recent deploy',
     'recommended_action','Rollback deployment',
     'steps',JSON_ARRAY('Confirm p95 latency spike correlates with recent deployment','Identify deployment version','Execute rollback to previous stable version','Verify p95 latency returns to baseline within 5 minutes'),
     'rollback','Re-deploy the rolled-back version if rollback worsens the issue',
     'approval_expires_at','2027-10-22T00:00:00Z','source','backend/database/migrations/20261022_missing_service_runbooks.sql'),
   0, 0, 'release-owner', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000'),

  ('b1000000-0000-4000-8000-000000000005', 'global', 1, SHA2('payments-api-down-playbook', 256),
   'approved', 'kaiops-platform-sre', 'high', 'mandatory',
   JSON_OBJECT('slug','payments-api-down-playbook','status','approved',
     'description','Restart payments-api service',
     'recommended_action','Restart payments-api service',
     'steps',JSON_ARRAY('Confirm payments-api is unreachable','Check error logs','Restart service','Verify payment transactions resume'),
     'rollback','Escalate to payments team on-call',
     'approval_expires_at','2027-10-22T00:00:00Z','source','backend/database/migrations/20261022_missing_service_runbooks.sql'),
   0, 0, 'release-owner', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000'),

  ('b1000000-0000-4000-8000-000000000006', 'global', 1, SHA2('robot-shop-cart-playbook', 256),
   'approved', 'kaiops-platform-sre', 'medium', 'mandatory',
   JSON_OBJECT('slug','robot-shop-cart-playbook','status','approved',
     'description','Restart the robot-shop cart service container',
     'recommended_action','Restart robot-shop-cart container',
     'steps',JSON_ARRAY('Confirm rs-cart:8080 is unreachable','Restart robot-shop-cart container','Verify cart endpoint responds'),
     'rollback','Check Redis connectivity for cart session store',
     'approval_expires_at','2027-10-22T00:00:00Z','source','backend/database/migrations/20261022_missing_service_runbooks.sql'),
   0, 0, 'release-owner', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000'),

  ('b1000000-0000-4000-8000-000000000007', 'global', 1, SHA2('robot-shop-rabbitmq-playbook', 256),
   'approved', 'kaiops-platform-sre', 'medium', 'mandatory',
   JSON_OBJECT('slug','robot-shop-rabbitmq-playbook','status','approved',
     'description','Restart the robot-shop RabbitMQ container',
     'recommended_action','Restart robot-shop RabbitMQ container',
     'steps',JSON_ARRAY('Confirm RabbitMQ exporter is unreachable','Check RabbitMQ container logs for crash or OOM','Restart rs-rabbitmq container via docker-compose executor','Verify exporter scrape resumes within 30s'),
     'rollback','Check disk space on RabbitMQ data volume',
     'approval_expires_at','2027-10-22T00:00:00Z','source','backend/database/migrations/20261022_missing_service_runbooks.sql'),
   0, 0, 'release-owner', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000'),

  ('b1000000-0000-4000-8000-000000000008', 'global', 1, SHA2('robot-shop-shipping-playbook', 256),
   'approved', 'kaiops-platform-sre', 'medium', 'mandatory',
   JSON_OBJECT('slug','robot-shop-shipping-playbook','status','approved',
     'description','Restart the robot-shop shipping service container',
     'recommended_action','Restart robot-shop-shipping container',
     'steps',JSON_ARRAY('Confirm rs-shipping:8080 is unreachable','Restart rs-shipping container','Verify shipping endpoint responds'),
     'rollback','Check RabbitMQ connectivity from shipping service',
     'approval_expires_at','2027-10-22T00:00:00Z','source','backend/database/migrations/20261022_missing_service_runbooks.sql'),
   0, 0, 'release-owner', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000', '2026-10-22 00:00:00.000000')

ON DUPLICATE KEY UPDATE
  approval_status = VALUES(approval_status), owner = VALUES(owner),
  risk_level = VALUES(risk_level), content = VALUES(content),
  approved_by = VALUES(approved_by), approved_at = VALUES(approved_at),
  last_validated_at = VALUES(last_validated_at);

INSERT INTO runbook_approvals (approval_id, runbook_id, version, status, approver, approver_role, reason, approved_at)
VALUES
  ('b2000000-0000-4000-8000-000000000001', 'b1000000-0000-4000-8000-000000000001', 1, 'approved', 'release-owner', 'release-owner', 'Immutable catalog approval', '2026-10-22 00:00:00.000000'),
  ('b2000000-0000-4000-8000-000000000002', 'b1000000-0000-4000-8000-000000000002', 1, 'approved', 'release-owner', 'release-owner', 'Immutable catalog approval', '2026-10-22 00:00:00.000000'),
  ('b2000000-0000-4000-8000-000000000003', 'b1000000-0000-4000-8000-000000000003', 1, 'approved', 'release-owner', 'release-owner', 'Immutable catalog approval', '2026-10-22 00:00:00.000000'),
  ('b2000000-0000-4000-8000-000000000004', 'b1000000-0000-4000-8000-000000000004', 1, 'approved', 'release-owner', 'release-owner', 'Immutable catalog approval', '2026-10-22 00:00:00.000000'),
  ('b2000000-0000-4000-8000-000000000005', 'b1000000-0000-4000-8000-000000000005', 1, 'approved', 'release-owner', 'release-owner', 'Immutable catalog approval', '2026-10-22 00:00:00.000000'),
  ('b2000000-0000-4000-8000-000000000006', 'b1000000-0000-4000-8000-000000000006', 1, 'approved', 'release-owner', 'release-owner', 'Immutable catalog approval', '2026-10-22 00:00:00.000000'),
  ('b2000000-0000-4000-8000-000000000007', 'b1000000-0000-4000-8000-000000000007', 1, 'approved', 'release-owner', 'release-owner', 'Immutable catalog approval', '2026-10-22 00:00:00.000000'),
  ('b2000000-0000-4000-8000-000000000008', 'b1000000-0000-4000-8000-000000000008', 1, 'approved', 'release-owner', 'release-owner', 'Immutable catalog approval', '2026-10-22 00:00:00.000000')
ON DUPLICATE KEY UPDATE
  status = VALUES(status), approver = VALUES(approver),
  reason = VALUES(reason), approved_at = VALUES(approved_at);
