"""Stream a consistent KaiMS logical backup to a compressed host file."""
import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", default="kaims-mysql-1")
    parser.add_argument("--database", default="kaiops")
    parser.add_argument("--directory", default="backend/retention-archives/backups")
    args = parser.parse_args()
    if args.container == "kaims-mysql-1" and subprocess.run(["docker", "inspect", args.container], capture_output=True).returncode != 0:
        if subprocess.run(["docker", "inspect", "kaims-latest-mysql-1"], capture_output=True).returncode == 0:
            args.container = "kaims-latest-mysql-1"
    if not re.fullmatch(r"[A-Za-z0-9_]+", args.database):
        parser.error("Invalid database identifier")
    directory = Path(args.directory)
    directory.mkdir(parents=True, exist_ok=True)
    name = args.database + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".sql.gz"
    target = directory / name
    partial = directory / (name + ".partial")
    command = ('MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysqldump -uroot '
               '--single-transaction --quick --set-gtid-purged=OFF --no-tablespaces '
               '--routines --events --triggers --hex-blob --databases "$1"')
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(["docker", "exec", args.container, "sh", "-c", command, "backup", args.database],
                                   stdout=subprocess.PIPE, stderr=errors)
        try:
            with open(partial, "wb") as output:
                with gzip.GzipFile(fileobj=output, mode="wb", compresslevel=6) as compressed:
                    shutil.copyfileobj(process.stdout, compressed, length=1024*1024)
                output.flush()
                os.fsync(output.fileno())
            if process.wait() != 0:
                raise RuntimeError("mysqldump failed; incomplete backup was not promoted")
            with gzip.open(partial,"rb") as verify:
                while verify.read(1024*1024):
                    pass
            os.replace(partial,target)
            with open(target,"rb") as source:
                digest=hashlib.file_digest(source,"sha256").hexdigest()
            manifest={"file":target.name,"database":args.database,"sha256":digest,"bytes":target.stat().st_size,
                      "created_at":datetime.now(timezone.utc).isoformat(),"restore_tested":False}
            target.with_suffix(target.suffix+".json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
            print(json.dumps(manifest))
        except BaseException:
            if process.poll() is None:
                process.terminate()
                process.wait()
            raise
        finally:
            process.stdout.close()


if __name__ == "__main__":
    main()
