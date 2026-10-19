"""Controlled Linux kernel collector check; writes only a temporary 68 KiB file."""
import sys,os,tempfile,threading,time,json
from pathlib import Path
from disk_fanotify import observe
with tempfile.TemporaryDirectory(prefix='kaims-fanotify-test-') as d:
 p=Path(d)/'controlled-write.bin'
 def writer():
  time.sleep(0.2)
  with p.open('wb') as f:
   f.write(b'a'*4096);f.flush();os.fsync(f.fileno());time.sleep(0.2)
   f.write(b'b'*65536);f.flush();os.fsync(f.fileno())
 worker=threading.Thread(target=writer)
 rows,begin,end,coverage=observe(d,2,ready=worker.start)
 worker.join()
 matched=[r for r in rows if r['path']==str(p)]
 assert matched,rows
 assert matched[0]['pid']==os.getpid(),matched
 assert matched[0]['writer_attribution']=='kernel_modifying_process_pid'
 print(json.dumps({'controlled_test':True,'writer_pid_matches':True,'rows':matched,'coverage':coverage}))
