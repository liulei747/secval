"""单用户本机审计入口；不适合直接暴露公网。"""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from secval.models.audit import AuditBusyError, AuditTaskInput, AuditUnavailableError

router = APIRouter()


class AuditRequest(BaseModel):
    objective: str = Field(min_length=5, max_length=4000)
    repository_id: str = Field(min_length=1, max_length=200)
    snapshot_id: str = Field(min_length=1, max_length=200)
    max_steps: int = Field(default=12, ge=1, le=300)
    max_seconds: int = Field(default=300, ge=30, le=3600)
    allow_remote_code: bool = False
    security_context: str = Field(default="", max_length=12000)
    supplied_threat_model: str = Field(default="", max_length=12000)
    scope_paths: list[str] = Field(default_factory=list, max_length=30)
    independent_baseline: bool = True
    approved_config_paths: list[str] = Field(default_factory=list, max_length=30)
    allow_remote_config: bool = False


class ResumeRequest(BaseModel):
    max_steps: int = Field(default=12, ge=1, le=300)
    max_seconds: int = Field(default=300, ge=30, le=3600)
    allow_remote_code: bool = False
    allow_remote_config: bool = False


@router.post("/api/audits/{task_id}/resume", status_code=202)
def resume_audit(task_id: str, body: ResumeRequest, request: Request):
    try:
        return request.app.state.audit_service.resume(task_id, **body.model_dump())
    except KeyError:
        raise HTTPException(404, "任务不存在") from None
    except AuditBusyError as error:
        raise HTTPException(409, str(error)) from None
    except AuditUnavailableError as error:
        raise HTTPException(503, str(error)) from None
    except ValueError as error:
        raise HTTPException(400, str(error)) from None


@router.post("/api/audits", status_code=202)
def create_audit(body: AuditRequest, request: Request):
    try:
        command = AuditTaskInput(**body.model_dump())
        return request.app.state.audit_service.create(command)
    except AuditBusyError as error:
        raise HTTPException(409, str(error)) from None
    except AuditUnavailableError as error:
        raise HTTPException(503, str(error)) from None
    except ValueError as error:
        raise HTTPException(400, str(error)) from None


@router.get("/api/audits")
def list_audits(request: Request):
    return request.app.state.audit_service.list()


@router.get("/api/audits/{task_id}")
def get_audit(task_id: str, request: Request):
    try:
        return request.app.state.audit_service.get(task_id)
    except KeyError:
        raise HTTPException(404, "任务不存在") from None


@router.post("/api/audits/{task_id}/cancel")
def cancel_audit(task_id: str, request: Request):
    try:
        return request.app.state.audit_service.cancel(task_id)
    except KeyError:
        raise HTTPException(404, "任务不存在") from None


@router.get("/api/audits/{task_id}/report")
def get_report(task_id: str, request: Request):
    try:
        report = request.app.state.audit_service.report(task_id)
    except KeyError:
        raise HTTPException(404, "任务不存在") from None
    return JSONResponse(report, headers={"Content-Disposition": 'attachment; filename="secval-audit-report.json"',
                                         "Cache-Control": "no-store"})


@router.get("/audit", response_class=HTMLResponse)
def audit_page():
    return """<!doctype html><html lang="zh"><meta charset="utf-8">
<title>Secval 只读审计实验</title><style>
body{max-width:960px;margin:40px auto;font:16px system-ui;background:#f6f7fa;color:#243043}
textarea,select,button{padding:10px;margin:8px 0}textarea{width:95%;height:100px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:20px}
</style><h1>Secval · 只读审计实验</h1>
<p>仅分析已索引代码块，不保证完整覆盖。结果均需人工复核。禁止执行仓库代码。</p>
<select id="repo"></select><textarea id="goal" placeholder="例如：调查登录入口及认证控制，记录证据、反证和未确认项"></textarea>
<textarea id="context" maxlength="12000" placeholder="可选：实际部署方式、业务约束、攻击者权限；不要填写密钥"></textarea>
<textarea id="threat" maxlength="12000" placeholder="可选：已有威胁模型，原文保留；不要填写密钥"></textarea>
<textarea id="paths" placeholder="可选：限定审计文件或目录，每行一个仓库相对路径；留空表示全部索引范围"></textarea>
<textarea id="configs" placeholder="可选：明确批准读取的配置文件，每行一个精确相对路径；不要填写 .env 或密钥文件"></textarea>
<label>本次模型调用上限 <input id="steps" type="number" min="1" max="300" value="12"></label><br>
<label>本次时长预算（秒） <input id="seconds" type="number" min="30" max="3600" value="300"></label>
<p>增大预算会增加调用与费用。时长在请求之间检查，已发送请求可能超出该时长；不是费用上限。</p>
<label><input type="checkbox" id="baseline" checked>先建立独立上下文基线</label><br>
<label><input type="checkbox" id="consent">允许将任务及候选源码发送给审计模型API</label><br>
<label><input type="checkbox" id="configConsent">允许将选定配置正文发送给审计模型API（可能含凭据）</label><br>
<button id="start">开始调查</button><button id="cancel">取消当前任务</button>
<button id="resume">从检查点续跑（新任务）</button>
<button id="export">导出当前报告（含源码）</button>
<button id="refresh">刷新历史</button><select id="history"></select><pre id="out">等待任务</pre>
<script>
let current=null; const el=id=>document.getElementById(id);
const lines=id=>el(id).value.split(/\\r?\\n/).map(s=>s.trim()).filter(Boolean);
async function api(path,body){const r=await fetch(path,body?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{});const d=await r.json();if(!r.ok)throw Error(d.detail||r.status);return d;}
async function history(){const tasks=await api('/api/audits');el('history').replaceChildren();for(const t of tasks){const o=new Option(t.status+' · '+t.objective,t.id);el('history').add(o);}}
async function show(){if(current)el('out').textContent=JSON.stringify(await api('/api/audits/'+current),null,2);}
el('start').onclick=async()=>{try{const scope=JSON.parse(el('repo').value);const t=await api('/api/audits',{objective:el('goal').value,...scope,security_context:el('context').value,supplied_threat_model:el('threat').value,scope_paths:lines('paths'),approved_config_paths:lines('configs'),max_steps:Number(el('steps').value),max_seconds:Number(el('seconds').value),independent_baseline:el('baseline').checked,allow_remote_config:el('configConsent').checked,allow_remote_code:el('consent').checked});current=t.id;await show();await history();}catch(e){el('out').textContent=e.message;}};
el('resume').onclick=async()=>{if(!current)return;try{const t=await api('/api/audits/'+encodeURIComponent(current)+'/resume',{max_steps:Number(el('steps').value),max_seconds:Number(el('seconds').value),allow_remote_code:el('consent').checked,allow_remote_config:el('configConsent').checked});current=t.id;await show();await history();}catch(e){el('out').textContent=e.message;}};
el('cancel').onclick=async()=>{if(current){await api('/api/audits/'+current+'/cancel',{});await show();}};
el('export').onclick=()=>{if(current)window.location.href='/api/audits/'+encodeURIComponent(current)+'/report';};
el('refresh').onclick=history;el('history').onchange=()=>{current=el('history').value;show();};
setInterval(()=>show().catch(e=>el('out').textContent=e.message),3000);
api('/api/repositories').then(d=>{for(const r of d.repositories)el('repo').add(new Option(r.repository_id+' / '+r.snapshot_id,JSON.stringify({repository_id:r.repository_id,snapshot_id:r.snapshot_id})));}).catch(e=>el('out').textContent=e.message);
history().catch(e=>el('out').textContent=e.message);
</script></html>"""
