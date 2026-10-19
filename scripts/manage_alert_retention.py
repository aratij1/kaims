"""Archive only old unlinked alerts transactionally; dry-run by default, reversible by batch."""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

ROOT=Path(__file__).resolve().parents[1]
COLUMNS=("id","tenant_id","source","name","service","environment","severity","fingerprint","correlation_id","payload","created_at","updated_at")
FORMATTED="CONCAT(SUBSTR(a.id,1,8),'-',SUBSTR(a.id,9,4),'-',SUBSTR(a.id,13,4),'-',SUBSTR(a.id,17,4),'-',SUBSTR(a.id,21,12))"
ELIGIBLE="""a.tenant_id=%s AND a.created_at < %s
 AND NOT EXISTS (SELECT 1 FROM incident_occurrences o WHERE o.tenant_id=a.tenant_id AND o.occurrence_id=a.id)
 AND NOT EXISTS (SELECT 1 FROM incident_events e WHERE e.tenant_id=a.tenant_id AND e.alert_id=a.id)
 AND NOT EXISTS (SELECT 1 FROM analysis_requests r WHERE r.tenant_id=a.tenant_id AND r.alert_id=a.id)
 AND NOT EXISTS (SELECT 1 FROM incident_investigation_bindings b WHERE b.tenant_id=a.tenant_id AND b.alert_id=a.id)
 AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.tenant_id=a.tenant_id AND
   (JSON_CONTAINS(i.payload,JSON_QUOTE(a.id),'$.alert_ids') OR JSON_CONTAINS(i.payload,JSON_QUOTE("""+FORMATTED+"""),'$.alert_ids')))
 AND NOT EXISTS (SELECT 1 FROM context_snapshots c WHERE c.tenant_id=a.tenant_id AND
   JSON_UNQUOTE(JSON_EXTRACT(c.payload,'$.alert.id')) IN (a.id,"""+FORMATTED+"""))"""
DDL="""CREATE TABLE IF NOT EXISTS retained_alert_archives (
 tenant_id VARCHAR(128) NOT NULL, alert_id CHAR(32) NOT NULL,
 batch_id CHAR(36) NOT NULL, archived_at DATETIME(6) NOT NULL,
 record_json LONGTEXT NOT NULL, checksum_sha256 CHAR(64) NOT NULL,
 PRIMARY KEY(tenant_id,alert_id), KEY idx_retained_alert_batch(tenant_id,batch_id)
) ENGINE=InnoDB"""

def encode_record(row):
    record={k:(v.strftime("%Y-%m-%d %H:%M:%S.%f") if isinstance(v,datetime) else v) for k,v in row.items()}
    return json.dumps(record,sort_keys=True,separators=(",",":"),ensure_ascii=False)

def validate_policy(policy):
    if policy.get("schema_version")!="kaims.alert-retention.v1" or not policy.get("tenant_id"):
        raise ValueError("Invalid retention policy identity")
    if policy.get("unlinked_live_days",0)<30 or policy.get("archive_minimum_days",0)<365:
        raise ValueError("Retention cannot be shorter than the selected policy")
    if policy.get("automatic_archive_deletion") is not False or policy.get("preserve_incident_and_analysis_references") is not True:
        raise ValueError("Referenced evidence and archived copies must be retained")
    if not 1<=policy.get("batch_size",0)<=500:raise ValueError("Invalid batch size")

def eligibility_sql(cursor):
    cursor.execute("SELECT COUNT(*) AS present FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='context_snapshots' AND index_name='idx_context_snapshots_retention_alert'")
    if not cursor.fetchone()["present"]:
        raise RuntimeError("Apply 20261015_snapshot_alert_retention_index.sql before alert retention; JSON scans are unsafe on large snapshot tables")
    start = ELIGIBLE.index(" AND NOT EXISTS (SELECT 1 FROM context_snapshots")
    return ELIGIBLE[:start] + " AND a.inbox_canonical_incident_id IS NULL AND NOT EXISTS (SELECT 1 FROM context_snapshots c WHERE c.tenant_id=a.tenant_id AND c.retention_alert_id=a.id)"

def run(connection,policy,*,execute=False,restore_batch=None):
    validate_policy(policy)
    tenant=policy["tenant_id"];cutoff=datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(days=policy["unlinked_live_days"])
    batch=str(UUID(restore_batch)) if restore_batch else str(uuid4())
    with connection.cursor() as cursor:
        eligible = eligibility_sql(cursor) if not restore_batch else None
        if not execute:
            cursor.execute("SELECT /*+ MAX_EXECUTION_TIME(30000) */ COUNT(*) AS eligible FROM alerts a WHERE "+eligible,(tenant,cutoff))
            return {"dry_run":True,"eligible":cursor.fetchone()["eligible"],"cutoff":str(cutoff),"policy":policy}
        cursor.execute(DDL)
    connection.commit()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        connection.begin()
        with connection.cursor() as cursor:
            if restore_batch:
                cursor.execute("SELECT * FROM retained_alert_archives WHERE tenant_id=%s AND batch_id=%s FOR UPDATE",(tenant,batch))
                rows=cursor.fetchall();restored=0
                for archived in rows:
                    raw=archived["record_json"]
                    if hashlib.sha256(raw.encode()).hexdigest()!=archived["checksum_sha256"]:raise ValueError("Archive checksum mismatch")
                    row=json.loads(raw)
                    if row["tenant_id"]!=tenant or row["id"]!=archived["alert_id"]:raise ValueError("Archive identity mismatch")
                    cursor.execute("SELECT * FROM alerts WHERE tenant_id=%s AND id=%s FOR UPDATE",(tenant,row["id"]))
                    existing=cursor.fetchone()
                    if existing:
                        if encode_record(existing)!=raw:raise ValueError("Restore would overwrite a changed alert")
                        continue
                    cursor.execute("INSERT INTO alerts ("+",".join(COLUMNS)+") VALUES ("+",".join(["%s"]*len(COLUMNS))+")",tuple(row[k] for k in COLUMNS));restored+=1
                result={"restored":restored,"batch_id":batch}
            else:
                cursor.execute("SELECT /*+ MAX_EXECUTION_TIME(30000) */ a.* FROM alerts a WHERE "+eligible+" ORDER BY a.created_at,a.id LIMIT %s FOR UPDATE",(tenant,cutoff,policy["batch_size"]))
                rows=cursor.fetchall()
                for row in rows:
                    raw=encode_record(row);checksum=hashlib.sha256(raw.encode()).hexdigest()
                    cursor.execute("SELECT checksum_sha256 FROM retained_alert_archives WHERE tenant_id=%s AND alert_id=%s FOR UPDATE",(tenant,row["id"]))
                    existing=cursor.fetchone()
                    if existing and existing["checksum_sha256"]!=checksum:raise ValueError("Existing archive differs; source retained")
                    if not existing:
                        cursor.execute("INSERT INTO retained_alert_archives VALUES (%s,%s,%s,UTC_TIMESTAMP(6),%s,%s)",(tenant,row["id"],batch,raw,checksum))
                    cursor.execute("DELETE FROM alerts WHERE tenant_id=%s AND id=%s",(tenant,row["id"]))
                    if cursor.rowcount!=1:raise ValueError("Source alert changed during archive")
                result={"archived":len(rows),"batch_id":batch,"cutoff":str(cutoff)}
        connection.commit();return result
    except Exception:
        connection.rollback();raise

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy",default=str(ROOT/"backend/config/alert-retention.json"))
    parser.add_argument("--execute",action="store_true")
    parser.add_argument("--restore-batch")
    args=parser.parse_args()
    if args.restore_batch and not args.execute:parser.error("Restoration requires --execute")
    sys.path.insert(0,str(ROOT/"backend/src/common"))
    from common.config import get_settings
    from sqlalchemy.engine import make_url
    import pymysql
    url=make_url(get_settings().database_url)
    connection=pymysql.connect(host=url.host,port=url.port or 3306,user=url.username,password=url.password,database=url.database,
        charset="utf8mb4",cursorclass=pymysql.cursors.DictCursor,autocommit=False,read_timeout=60,write_timeout=60)
    try:print(json.dumps(run(connection,json.loads(Path(args.policy).read_text()),execute=args.execute,restore_batch=args.restore_batch),indent=2))
    finally:connection.close()

if __name__=="__main__":main()
