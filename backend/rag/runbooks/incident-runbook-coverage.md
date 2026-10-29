kind: runbook
title: Incident runbook coverage matrix
services: airflow, cdc-pipeline, customer-dimension, customer-ingestion, daily-sales-report, data-ingestion, data-pipeline, data-warehouse, dq-framework, kafka-ingestion, oracle-source, orders-db, payments, powerbi-reporting, replication-service, sales-fact, sales-fact-table, snowflake, spark-cluster, transaction-feed, unknown
owner_team: platform-ops
last_reviewed: 2026-07-08
source_system: internal
source_ref: RAG-COVERAGE-RUNBOOKS

# Incident Runbook Coverage Matrix

This document ensures each incident/alert has runbook coverage references.

## Covered Incidents
- DW-1001 | ETL Job Failure | airflow
- DW-1002 | Data Load Delay | data-ingestion
- DW-1003 | Source System Unavailable | oracle-source
- DW-1004 | Kafka Consumer Lag High | kafka-ingestion
- DW-1005 | Data Quality Check Failed | dq-framework
- DW-1006 | Missing Daily Partition | sales-fact-table
- DW-1007 | Warehouse Storage Usage High | snowflake
- DW-1008 | Query Performance Degradation | data-warehouse
- DW-1009 | Replication Lag Exceeded Threshold | replication-service
- DW-1010 | Schema Drift Detected | customer-ingestion
- DW-1011 | Late Arriving Data | transaction-feed
- DW-1012 | Dimension Load Failure | customer-dimension
- DW-1013 | Fact Table Record Count Mismatch | sales-fact
- DW-1014 | Airflow Scheduler Down | airflow
- DW-1015 | Spark Executor Memory Exhausted | spark-cluster
- DW-1016 | Failed CDC Processing | cdc-pipeline
- DW-1017 | Business SLA Missed | daily-sales-report
- DW-1018 | Data Pipeline Backlog Growing | data-pipeline
- DW-1019 | Unauthorized Data Access Attempt | data-warehouse
- DW-1020 | Dashboard Refresh Failure | powerbi-reporting
- INC-8842 | INC-8842 payment latency after Deployment 2.5 | payments
- INC-9011 | INC-9011 orders database replica lag | orders-db
- RAG-DOC | RAG_doc | unknown
