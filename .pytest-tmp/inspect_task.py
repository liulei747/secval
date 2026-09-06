import json, urllib.request
t = json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/audits/e2521fa3996b464fad34b4f119fc5084'))
print('top keys:', sorted(t.keys()))
print('events count:', len(t.get('events', [])))
if t.get('events'): print('event keys:', sorted(t['events'][0].keys()))
print('model_requests count:', len(t.get('model_requests', [])))
if t.get('model_requests'): print('req keys:', sorted(t['model_requests'][-1].keys()))
inv = t.get('investigations') or []
if inv:
    i = inv[-1]
    print('investigation keys:', sorted(i.keys()))
    revs = i.get('reviews') or []
    if revs: print('review keys:', sorted(revs[-1].keys()))
for w in (t.get('agent_tasks') or []):
    print('worker:', w.get('id'), w.get('role'), w.get('status'), 'result keys:', sorted((w.get('result') or {}).keys()))
print('report exists:', bool(t.get('report')), 'draft:', bool(t.get('draft_report')))
