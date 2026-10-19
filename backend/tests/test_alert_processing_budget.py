import asyncio
from time import monotonic
import pytest
from pydantic import ValidationError
from common.config import Settings
from common import alert_processing_budget as budget

class Store:
 def __init__(self): self.entries={}; self.waiting={}; self.outage=False
 async def eval(self, script, count, *values):
  key=values[0];args=values[count:]
  if self.outage: raise ConnectionError('unavailable')
  self.entries={k:v for k,v in self.entries.items() if v>monotonic()}
  if not args: return [len(self.entries),len(self.waiting)]
  limit,ttl,token=args
  if len(self.entries)>=limit:
   self.waiting[token]=True;return 0
  self.waiting.pop(token,None)
  self.entries[token]=monotonic()+ttl/1000
  return 1
 async def zrem(self,key,token):
  (self.waiting if key.endswith(':waiting') else self.entries).pop(token,None)

@pytest.mark.asyncio
async def test_replicas_share_50_slots_and_excess_work_resumes(monkeypatch):
 store=Store();monkeypatch.setattr(budget,'client_for',lambda settings:store)
 release=asyncio.Event();started=0;running=0;peak=0
 async def handle(payload):
  nonlocal started,running,peak
  started+=1;running+=1;peak=max(peak,running)
  await release.wait();running-=1
 settings=[Settings(SERVICE_NAME='worker-a'),Settings(SERVICE_NAME='worker-b')]
 tasks=[asyncio.create_task(budget.run_handler(settings[i%2],'context-events',handle,{})) for i in range(75)]
 try:
  await asyncio.sleep(.05)
  assert started==50 and peak==50
  assert (await budget.capacity(settings[0]))['active']==50
  assert (await budget.capacity(settings[0]))['waiting']==25
  release.set()
  await asyncio.wait_for(asyncio.gather(*tasks),3)
  assert started==75 and peak<=50 and not store.entries
 finally:
  for task in tasks:task.cancel()
  await asyncio.gather(*tasks,return_exceptions=True)

@pytest.mark.asyncio
async def test_store_outage_waits_without_starting_or_consuming_handler_timeout(monkeypatch):
 store=Store();store.outage=True;monkeypatch.setattr(budget,'client_for',lambda settings:store)
 called=[]
 async def handle(payload):called.append(True)
 settings=Settings(RABBITMQ_HANDLER_TIMEOUT_SECONDS=.01)
 task=asyncio.create_task(budget.run_handler(settings,'raw-alerts',handle,{}))
 try:
  await asyncio.sleep(.05)
  assert not called and not task.done()
  assert (await budget.capacity(settings))['active'] is None
  store.outage=False
  await asyncio.wait_for(task,2)
  assert called and not store.entries
 finally:
  task.cancel();await asyncio.gather(task,return_exceptions=True)

@pytest.mark.asyncio
async def test_failed_and_cancelled_handlers_release_slots(monkeypatch):
 store=Store();monkeypatch.setattr(budget,'client_for',lambda settings:store)
 async def broken(payload):raise ValueError('failed')
 with pytest.raises(ValueError):await budget.run_handler(Settings(),'context-events',broken,{})
 assert not store.entries
 async def slow(payload):await asyncio.Event().wait()
 task=asyncio.create_task(budget.run_handler(Settings(),'context-events',slow,{}))
 await asyncio.sleep(.01);task.cancel()
 await asyncio.gather(task,return_exceptions=True)
 assert not store.entries

def test_budget_cannot_be_configured_above_50():
 with pytest.raises(ValidationError):Settings(ALERT_PROCESSING_LIMIT=51)

@pytest.mark.asyncio
async def test_collection_waits_for_capacity_before_claiming_a_durable_job(monkeypatch):
 import ast,os
 from pathlib import Path
 from types import SimpleNamespace
 from common import enrichment_scheduler
 source=Path('ai-workbench/src/context-agent/app.py').read_text(encoding='utf-8')
 node=next(n for n in ast.parse(source).body if isinstance(n,ast.AsyncFunctionDef) and n.name=='_context_enrichment_worker')
 admitted=asyncio.Event();claimed=asyncio.Event()
 async def run(settings,topic,handler,payload,**kwargs):
  assert kwargs['timeout_seconds']==120
  await admitted.wait()
  await handler(payload)
 monkeypatch.setattr(budget,'run_handler',run)
 async def persist(factory,operation):return await operation(None)
 monkeypatch.setattr(enrichment_scheduler,'persist_collected_evidence',persist)
 class Repository:
  def __init__(self,session):pass
  async def claim_context_enrichment_jobs(self,**kwargs):
   assert kwargs['limit']==1
   claimed.set();return []
 scope={'FastAPI':object,'os':os,'asyncio':asyncio,'settings':SimpleNamespace(service_name='context-agent',database_enabled=True),
        'ContextEnrichmentRepository':Repository,'logger':SimpleNamespace(exception=lambda *args,**kwargs:None)}
 exec(compile(ast.Module(body=[node],type_ignores=[]),'<collection-worker>','exec'),scope)
 app=SimpleNamespace(state=SimpleNamespace(session_factory=object()))
 task=asyncio.create_task(scope['_context_enrichment_worker'](app))
 try:
  await asyncio.sleep(.02)
  assert not claimed.is_set()
  admitted.set();await asyncio.wait_for(claimed.wait(),1)
 finally:
  task.cancel();await asyncio.gather(task,return_exceptions=True)

@pytest.mark.asyncio
async def test_cancelled_backlog_delivery_does_not_start_handler(monkeypatch):
 from common import message_processing
 store=Store();monkeypatch.setattr(budget,'client_for',lambda settings:store)
 async def cancelled(settings,payload):return True
 monkeypatch.setattr(message_processing,'processing_cancelled',cancelled)
 called=[]
 async def handler(payload):called.append(True)
 await budget.run_handler(Settings(),'raw-alerts',handler,{'alert_id':'cancelled-alert'})
 assert not called and not store.entries
