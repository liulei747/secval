"""统一测试工作台：一个页面串起上传、索引、搜索、审计与关系查询。"""

from fastapi.responses import HTMLResponse
from fastapi import APIRouter

router = APIRouter()


@router.get("/workbench", response_class=HTMLResponse)
def workbench_page():
    return """<!doctype html><html lang="zh"><meta charset="utf-8">
<title>Secval 测试工作台</title><style>
body{max-width:1180px;margin:24px auto;font:15px system-ui;background:#f6f7fa;color:#243043;padding:0 16px}
h1{font-size:22px}h2{font-size:17px;margin:14px 0 6px}h3{font-size:15px;margin:10px 0 4px}
section{background:#fff;border:1px solid #dde3ec;border-radius:10px;padding:14px 18px;margin:14px 0}
label{display:block;margin:6px 0}input,select,textarea{padding:6px;margin:4px 0;max-width:100%}
textarea{width:98%}input[type=number]{width:90px}input[type=text]{width:320px}
button{padding:7px 14px;margin:4px 6px 4px 0;cursor:pointer;border:1px solid #4a6fa5;background:#eef3fb;border-radius:6px}
button.primary{background:#2b6cb0;color:#fff;border-color:#2b6cb0}
button:disabled{opacity:.5;cursor:not-allowed}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f2f4f8;padding:12px;border-radius:6px;max-height:420px;overflow:auto}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid #d5dbe6;padding:5px 8px;text-align:left;font-size:14px;vertical-align:top}
th{background:#eef1f6}
.status{font-weight:bold}.ok{color:#177245}.bad{color:#b03030}.warn{color:#9a6700}
.muted{color:#67748a;font-size:13px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;background:#e3e8f0;margin-right:4px}
.nav{display:flex;gap:14px;align-items:center;margin:10px 0}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.flex{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.hidden{display:none}
</style>
<h1>Secval 统一测试工作台</h1>
<p class="muted">当前 API 服务包含全部功能；旧入口保留：<a href="/audit" target="_blank">审计</a> · <a href="/graph" target="_blank">关系查询</a> · <a href="/docs" target="_blank">API 文档</a></p>

<section id="secHealth">
<h2>服务与当前上下文</h2>
<div id="healthLine" class="status">检查服务中……</div>
<div class="flex" style="margin-top:6px">
  <button onclick="loadAll()">刷新全部</button>
  <span id="queueLine" class="muted"></span>
</div>
<h3>当前仓库 / 快照 / 批次</h3>
<table id="repoTable"><thead><tr><th>仓库</th><th>快照</th><th>代码块数</th><th>操作</th></tr></thead><tbody></tbody></table>
<p class="muted">审计使用仓库+快照定位；关系查询页面可核对具体索引批次。</p>
</section>

<section id="secPipeline">
<h2>1. 上传与索引</h2>
<div class="grid">
<div>
<h3>上传 ZIP</h3>
<label>服务器目录名 <input type="text" id="upDir" value="demo-project"></label>
<label><input type="checkbox" id="upReplace"> 允许替换同名目录</label>
<label>ZIP 文件 <input type="file" id="upZip" accept=".zip"></label>
<button class="primary" onclick="uploadZip()">上传 ZIP</button>
<div id="upStatus" class="muted"></div>
</div>
<div>
<h3>建立索引</h3>
<label>仓库 ID <input type="text" id="idxRepo" value="demo-project"></label>
<label>快照 ID <input type="text" id="idxSnap" value="demo-project-main"></label>
<label>版本 <input type="text" id="idxVer" value="main"></label>
<label>服务器路径 <input type="text" id="idxPath" value="demo-project"></label>
<button class="primary" onclick="createIndex()">提交索引任务</button>
<div id="idxStatus" class="muted"></div>
<h3>最近索引任务</h3>
<table id="jobTable"><thead><tr><th>任务</th><th>状态</th><th>阶段</th><th>更新时间</th><th>操作</th></tr></thead><tbody></tbody></table>
</div>
</div>
</section>

<section id="secSearch">
<h2>2. 混合搜索</h2>
<div class="flex">
<label>仓库 <select id="schRepo"></select></label>
<label>问题 <input type="text" id="schText" value="认证在哪里实现？" style="width:380px"></label>
<label>Top K <input type="number" id="schK" value="5" min="1" max="100" style="width:70px"></label>
<button class="primary" onclick="doSearch()">搜索</button>
</div>
<div id="schStatus" class="muted"></div>
<pre id="schOut" class="hidden"></pre>
</section>

<section id="secAudit">
<h2>3. 协作审计</h2>
<div class="grid">
<div>
<h3>创建任务</h3>
<label>仓库 / 快照 <select id="audRepo"></select></label>
<label>调查目标 <textarea id="audGoal" rows="3">调查登录入口及认证控制，记录证据、反证和未确认项</textarea></label>
<label>部署约束（可选） <textarea id="audCtx" rows="2"></textarea></label>
<div class="flex">
<label>调用上限 <input type="number" id="audSteps" value="12" min="1" max="300" style="width:80px"></label>
<label>时长（秒） <input type="number" id="audSecs" value="300" min="30" max="3600" style="width:80px"></label>
<label>并发 Agent <input type="number" id="audAgents" value="3" min="2" max="4" style="width:70px"></label>
</div>
<label><input type="checkbox" id="audBaseline" checked> 独立基线</label>
<label><input type="checkbox" id="audConsent"> 允许将候选源码发送给审计模型 API</label>
<label><input type="checkbox" id="audCfgConsent"> 允许发送选定配置文件正文</label>
<button class="primary" onclick="createAudit()">开始审计</button>
<div id="audCreateStatus" class="muted"></div>
</div>
<div>
<h3>历史任务</h3>
<div class="flex">
<select id="audHistory" style="min-width:280px"></select>
<button onclick="refreshAudits()">刷新</button>
<button onclick="cancelAudit()">取消</button>
<button onclick="resumeAudit()">续跑</button>
<button onclick="exportReport()">导出报告</button>
</div>
<div id="audSummary" class="muted" style="margin-top:8px"></div>
<h3>Agent 分工与状态</h3>
<table id="workerTable"><thead><tr><th>编号</th><th>角色</th><th>分工</th><th>状态</th><th>调用</th><th>停止原因</th></tr></thead><tbody></tbody></table>
<h3>工具调用 / 模型请求记录</h3>
<table id="reqTable"><thead><tr><th>#</th><th>阶段</th><th>状态</th><th>耗时(秒)</th><th>输入字符</th><th>Tokens(入/出/总)</th></tr></thead><tbody></tbody></table>
</div>
</div>
<h3>候选问题</h3>
<div id="candList" class="muted">尚无候选。</div>
<h3>复核结论</h3>
<div id="reviewList" class="muted">尚无复核。</div>
<h3>报告摘要 / 未决项</h3>
<div class="flex"><button onclick="loadReport()">读取报告</button><span id="repLine" class="muted"></span></div>
<pre id="repOut" class="hidden"></pre>
<details><summary>原始任务 JSON</summary><pre id="audRaw"></pre></details>
</section>

<section id="secGraph">
<h2>4. 关系查询</h2>
<div class="flex">
<label>仓库 <select id="gRepo"></select></label>
<label>符号 <input type="text" id="gSymbol" value="" placeholder="如 verify_token"></label>
<button onclick="graphQuery('callers')">调用者</button>
<button onclick="graphQuery('callees')">被调用</button>
<button onclick="graphQuery('symbols')">符号声明</button>
</div>
<div id="gStatus" class="muted"></div>
<pre id="gOut" class="hidden"></pre>
</section>

<script>
const el=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function api(path,opts){const r=await fetch(path,opts);const t=await r.text();let d;try{d=JSON.parse(t)}catch{d={raw:t}}if(!r.ok)throw Error(d.detail||d.raw||r.status);return d;}
const jsonPost=(url,body)=>({method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});

async function loadAll(){await Promise.allSettled([loadHealth(),loadRepos(),loadJobs(),refreshAudits()]);}

async function loadHealth(){
  try{const d=await api('/api/health');
    const parts=Object.entries(d).filter(([k,v])=>typeof v==='string').map(([k,v])=>k+':'+v);
    el('healthLine').innerHTML='<span class="ok">正常</span> — '+esc(parts.join('；'));
  }catch(e){el('healthLine').innerHTML='<span class="bad">不可用：'+esc(e.message)+'</span>';}
  try{const q=await api('/api/task-queues');
    el('queueLine').textContent='队列：索引 排队'+q.index.queued+' 执行'+q.index.running+'；审计 排队'+q.audit.queued+' 执行'+q.audit.running;
  }catch(e){}
}

async function loadRepos(){
  try{const d=await api('/api/repositories');const rows=d.repositories||[];
    el('repoTable').querySelector('tbody').innerHTML=rows.map(r=>
      '<tr><td>'+esc(r.repository_id)+'</td><td>'+esc(r.snapshot_id)+'</td><td>'+r.chunk_count+'</td><td>'+
      '<button onclick=\'useRepo("'+esc(r.repository_id)+'","'+esc(r.snapshot_id)+'")\'>设为当前</button></td></tr>').join('');
    const opts=rows.map(r=>'<option value=\''+esc(JSON.stringify({repository_ids:[r.repository_id],snapshot_ids:[r.snapshot_id]}))+'\'>'+esc(r.repository_id+' / '+r.snapshot_id)+' ('+r.chunk_count+')</option>').join('');
    el('schRepo').innerHTML=opts||'<option value="">无</option>';
    el('audRepo').innerHTML=rows.map(r=>'<option value=\''+esc(JSON.stringify({repository_id:r.repository_id,snapshot_id:r.snapshot_id}))+'\'>'+esc(r.repository_id+' / '+r.snapshot_id)+'</option>').join('');
    el('gRepo').innerHTML=rows.map(r=>'<option value=\''+esc(JSON.stringify({repository_id:r.repository_id,snapshot_id:r.snapshot_id}))+'\'>'+esc(r.repository_id+' / '+r.snapshot_id)+'</option>').join('');
  }catch(e){el('repoTable').querySelector('tbody').innerHTML='<tr><td colspan=4>加载失败：'+esc(e.message)+'</td></tr>';}
}
function useRepo(repo,snap){el('idxRepo').value=repo;el('idxSnap').value=snap;el('idxPath').value=repo;}

async function uploadZip(){
  const f=el('upZip').files[0];if(!f)return alert('先选择 ZIP');
  const fd=new FormData();fd.append('repository_directory',el('upDir').value);fd.append('replace_existing',el('upReplace').checked);fd.append('zip_file',f);
  el('upStatus').textContent='上传中……';
  try{const d=await api('/api/repositories/upload-zip',{method:'POST',body:fd});
    el('upStatus').innerHTML='<span class="ok">上传成功</span>：'+d.uploaded_files+' 个文件，'+Math.round(d.uploaded_bytes/1024)+' KB'+(d.replaced_existing?'（替换旧目录）':'');
  }catch(e){el('upStatus').innerHTML='<span class="bad">失败：'+esc(e.message)+'</span>';}
}

async function createIndex(){
  const body={repository_id:el('idxRepo').value,repository_name:el('idxRepo').value,repository_path:el('idxPath').value,snapshot_id:el('idxSnap').value,version:el('idxVer').value};
  el('idxStatus').textContent='提交中……';
  try{const d=await api('/api/repositories/index-jobs',jsonPost('/api/repositories/index-jobs',body));
    el('idxStatus').innerHTML='<span class="ok">已排队</span> 任务 '+esc(d.id);
    await loadJobs();
  }catch(e){el('idxStatus').innerHTML='<span class="bad">失败：'+esc(e.message)+'</span>';}
}

async function loadJobs(){
  try{const jobs=await api('/api/repositories/index-jobs');
    el('jobTable').querySelector('tbody').innerHTML=jobs.slice().sort((a,b)=>String(b.created_at).localeCompare(String(a.created_at))).slice(0,8).map(j=>{
      const last=(j.stage_history||[]).slice(-1)[0]||{};
      const ops=[];
      if(j.status==='running'||j.status==='queued')ops.push('<button onclick=\'jobAction("'+j.id+'","cancel")\'>取消</button>');
      if(['failed','interrupted'].includes(j.status))ops.push('<button onclick=\'jobAction("'+j.id+'","resume")\'>续跑</button>');
      if(j.lease_state==='expired')ops.push('<button onclick=\'jobAction("'+j.id+'","recover-stale")\'>确认失联</button>');
      return '<tr><td>'+esc(j.id.slice(0,8))+'</td><td>'+esc(j.status)+'</td><td>'+esc(j.stage||'')+(last.status?' ('+esc(last.status)+')':'')+'</td><td>'+esc(j.updated_at||j.finished_at||j.started_at||'')+'</td><td>'+ops.join(' ')+'</td></tr>';
    }).join('')||'<tr><td colspan=5>暂无任务</td></tr>';
  }catch(e){el('idxStatus').textContent='索引任务读取失败：'+e.message;}
}
async function jobAction(id,action){try{await api('/api/repositories/index-jobs/'+id+'/'+action,jsonPost('/api/repositories/index-jobs/'+id+'/'+action,{}));await loadJobs();}catch(e){alert(e.message);}}

async function doSearch(){
  const scope=JSON.parse(el('schRepo').value||'{}');if(!scope.repository_ids)return alert('无可用索引');
  el('schStatus').textContent='搜索中……';el('schOut').classList.remove('hidden');
  try{const d=await api('/api/search',jsonPost('/api/search',{text:el('schText').value,repository_ids:scope.repository_ids,snapshot_ids:scope.snapshot_ids,top_k:Number(el('schK').value)}));
    el('schStatus').innerHTML='<span class="ok">返回 '+d.results.length+' 条</span>';
    el('schOut').textContent=d.results.map((r,i)=>(i+1)+'. '+r.relative_path+':'+r.start_line+'-'+r.end_line+' ['+r.chunk_type+']\n'+r.content.slice(0,400)).join('\n\n');
  }catch(e){el('schStatus').innerHTML='<span class="bad">失败：'+esc(e.message)+'</span>';}
}

async function refreshAudits(){
  try{const tasks=await api('/api/audits');
    el('audHistory').innerHTML=tasks.map(t=>'<option value="'+t.id+'">'+esc(t.status+' · '+(t.objective||'').slice(0,40))+'</option>').join('');
    if(tasks.length)await showAudit(tasks[0].id);
  }catch(e){}
}

async function showAudit(id){
  if(!id)return;
  try{const t=await api('/api/audits/'+id);
    el('audRaw').textContent=JSON.stringify(t,null,2);
    el('audSummary').innerHTML='任务 <b>'+esc(id.slice(0,8))+'</b> 状态 <span class="'+(t.status==='needs_review'?'ok':(t.status==='running'?'warn':'bad'))+'">'+esc(t.status)+'</span> · 模型调用 '+(t.model_calls||0)+'/'+t.max_steps+' · 并发 '+(t.parallel_agents||1)+(t.stop_reason?' · 停止原因: '+esc(t.stop_reason):'')+(t.error?' · 错误: '+esc(t.error):'');
    el('workerTable').querySelector('tbody').innerHTML=(t.agent_tasks||[]).map(w=>
      '<tr><td>'+esc(w.id)+'</td><td>'+esc(w.role)+'</td><td>'+esc((w.assignment||{}).title||'')+'</td><td>'+esc(w.effective_status||w.status)+(w.reused_result?'（复用）':'')+'</td><td>'+(w.calls||0)+'/'+(w.prior_calls||0)+'</td><td>'+esc(w.stop_reason||'')+'</td></tr>').join('')||'<tr><td colspan=6>无</td></tr>';
    el('reqTable').querySelector('tbody').innerHTML=(t.model_requests||[]).slice(-20).reverse().map(r=>
      '<tr><td>'+r.call+'</td><td>'+esc(r.phase||'')+'</td><td>'+esc(r.status||'')+'</td><td>'+(r.seconds??'')+'</td><td>'+(r.input_characters??'')+'</td><td>'+[r.prompt_tokens,r.completion_tokens,r.total_tokens].map(v=>v??'-').join('/')+'</td></tr>').join('')||'<tr><td colspan=6>无</td></tr>';
    el('candList').innerHTML=renderCands(t);
    el('reviewList').innerHTML=(t.independent_reviews||[]).map(v=>
      '<div><b>'+esc(v.investigation_id||'')+'</b> → '+esc(v.outcome||'')+(v.assessment?'：'+esc(v.assessment):'')+'</div>').join('')||'尚无复核。';
  }catch(e){el('audSummary').innerHTML='<span class="bad">'+esc(e.message)+'</span>';}
}

function renderCands(t){
  const invs=t.investigations||[];if(!invs.length)return '尚无候选。';
  const revMap={};(t.independent_reviews||[]).forEach(v=>{(revMap[v.investigation_id]=revMap[v.investigation_id]||[]).push(v);});
  return invs.map(inv=>{
    const revs=(inv.reviews||[]).concat(revMap[inv.id]||[]);
    const latest=revs[revs.length-1];
    const outcome=latest?latest.outcome:(inv.status||'');
    return '<div style="margin:8px 0;border-left:3px solid #8aa4c8;padding-left:10px">'+
      '<b>'+esc(inv.id||inv.boundary_id||'')+'</b> · 结论: <span class="'+(outcome==='supported'?'bad':(outcome==='refuted'?'ok':'warn'))+'">'+esc(outcome||'未复核')+'</span> — '+esc(inv.question||'')+
      '<br>核查点: '+esc(inv.control_to_check||'')+
      (inv.counterevidence?'<br>反证: '+esc(inv.counterevidence):'')+
      ((inv.unknowns||[]).length?'<br>未知项: '+esc(inv.unknowns.join('；')):'')+
      ((inv.evidence_ids||[]).length?'<br>证据: '+inv.evidence_ids.map(esc).join(', '):'')+
      (latest?'<br>复核评估: '+esc(latest.assessment||'')+(latest.limitations&&latest.limitations.length?'<br>复核局限: '+esc(latest.limitations.join('；')):''):'')+
      '</div>';
  }).join('');
}

async function createAudit(){
  const scope=JSON.parse(el('audRepo').value||'{}');if(!scope.repository_id)return alert('无可用索引');
  const body={objective:el('audGoal').value,...scope,security_context:el('audCtx').value,
    max_steps:Number(el('audSteps').value),max_seconds:Number(el('audSecs').value),
    parallel_agents:Number(el('audAgents').value),independent_baseline:el('audBaseline').checked,
    allow_remote_code:el('audConsent').checked,allow_remote_config:el('audCfgConsent').checked};
  el('audCreateStatus').textContent='提交中……';
  try{const t=await api('/api/audits',jsonPost('/api/audits',body));
    el('audCreateStatus').innerHTML='<span class="ok">已排队</span> 任务 '+esc(t.id.slice(0,8));
    el('audHistory').value=t.id;await showAudit(t.id);
  }catch(e){el('audCreateStatus').innerHTML='<span class="bad">失败：'+esc(e.message)+'</span>';}
}
async function cancelAudit(){const id=el('audHistory').value;if(!id)return;await api('/api/audits/'+id+'/cancel',jsonPost('/api/audits/'+id+'/cancel',{}));await showAudit(id);}
async function resumeAudit(){const id=el('audHistory').value;if(!id)return;
  try{const t=await api('/api/audits/'+id+'/resume',jsonPost('/api/audits/'+id+'/resume',{max_steps:Number(el('audSteps').value),max_seconds:Number(el('audSecs').value),allow_remote_code:el('audConsent').checked,allow_remote_config:el('audCfgConsent').checked}));
    el('audHistory').value=t.id;await showAudit(t.id);}catch(e){alert(e.message);}}
async function exportReport(){const id=el('audHistory').value;if(id)window.open('/api/audits/'+id+'/report');}

async function loadReport(){
  const id=el('audHistory').value;if(!id)return;
  try{const rep=await api('/api/audits/'+encodeURIComponent(id)+'/report');
    el('repOut').classList.remove('hidden');
    const c=rep.completion||{};
    el('repLine').textContent='收口: '+(c.state||'未知')+'；未收口原因: '+((c.pendingReasons||[]).join('；')||'无')+
      '；用量: 输入'+(rep.tokenUsage?.promptTokens||0)+'/输出'+(rep.tokenUsage?.completionTokens||0)+'='+ (rep.tokenUsage?.totalTokens||0)+' token';
    el('repOut').textContent=JSON.stringify({summary:rep.summary,findings:rep.findings,hypotheses:rep.hypotheses,unknowns:rep.unknowns,coverage:rep.coverage,completion:rep.completion,tokenUsage:rep.tokenUsage,stopReason:rep.stopReason},null,2);
  }catch(e){el('repLine').textContent='读取失败：'+e.message;}
}

async function graphQuery(kind){
  const scope=JSON.parse(el('gRepo').value||'{}');if(!scope.repository_id)return alert('无可用索引');
  const sym=el('gSymbol').value.trim();if(!sym&&kind!=='symbols')return alert('输入符号名');
  let runId='';
  try{const runs=await api('/api/repositories/index-runs?repository_id='+encodeURIComponent(scope.repository_id)+'&snapshot_id='+encodeURIComponent(scope.snapshot_id));runId=(runs&&runs[0])||'';}catch(e){}
  if(!runId){el('gStatus').innerHTML='<span class="bad">该快照没有可用索引批次</span>';return;}
  const body=kind==='symbols'?{repository_id:scope.repository_id,snapshot_id:scope.snapshot_id,index_run_id:runId,text:sym||''}:{repository_id:scope.repository_id,snapshot_id:scope.snapshot_id,index_run_id:runId,symbol:sym,limit:20};
  el('gStatus').textContent='查询中……';el('gOut').classList.remove('hidden');
  try{const d=await api('/api/code-graph/'+kind,jsonPost('/api/code-graph/'+kind,body));
    el('gStatus').innerHTML='<span class="ok">返回 '+((d.results||d.callers||d.callees||[]).length)+' 条</span>';
    el('gOut').textContent=JSON.stringify(d,null,2);
  }catch(e){el('gStatus').innerHTML='<span class="bad">失败：'+esc(e.message)+'</span>';}
}

setInterval(()=>{if(el('audHistory').value)showAudit(el('audHistory').value);loadHealth();loadJobs();},5000);
loadAll();
</script></html>"""
