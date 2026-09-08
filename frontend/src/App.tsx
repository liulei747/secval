import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  Database,
  Gauge,
  FolderUp,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Workflow,
} from "lucide-react";
import { ProjectManager } from "./ProjectManager";

type AnyRow = Record<string, any> & {
  call?: any;
  agent_id?: any;
  phase?: any;
  status?: any;
  input_characters?: any;
  prompt_tokens?: any;
  completion_tokens?: any;
  total_tokens?: any;
  seconds?: any;
};
const api = async (path: string, init?: RequestInit) => {
  const r = await fetch(path, init);
  const text = await r.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }
  if (!r.ok) throw new Error(data?.detail || String(data));
  return data;
};
const fmt = (n: number = 0) =>
  n >= 1e6
    ? (n / 1e6).toFixed(1) + "M"
    : n >= 1e3
      ? (n / 1e3).toFixed(1) + "K"
      : String(n);
const terminal = (s: string) =>
  [
    "needs_review",
    "failed",
    "cancelled",
    "interrupted",
    "budget_exhausted",
  ].includes(s);
const stages = [
  ["scope_freeze", "范围冻结"],
  ["entry_prefetch", "入口预取"],
  ["path_probe", "Path Probe"],
  ["validation_grouping", "验证分组"],
  ["evidence_supplement", "批量补证"],
  ["path_validation", "路径验证"],
  ["report_assembly", "报告收口"],
];
const viewTitles: Record<string, string> = {
  projects: "项目与索引",
  overview: "安全审计工作台",
  findings: "漏洞发现",
  evidence: "路径与证据",
  traffic: "模型流量",
  coverage: "覆盖与基准",
};

export function App() {
  const [tasks, setTasks] = useState<AnyRow[]>([]),
    [task, setTask] = useState<AnyRow | null>(null),
    [report, setReport] = useState<AnyRow | null>(null),
    [settings, setSettings] = useState<AnyRow>({}),
    [query, setQuery] = useState(""),
    [modal, setModal] = useState(false),
    [view, setView] = useState("overview"),
    [actionError, setActionError] = useState("");
  const loadShell = async () => {
    const [list, cfg] = await Promise.all([
      api("/api/audits"),
      api("/api/audit-settings"),
    ]);
    setTasks(list);
    setSettings(cfg);
    if (!task && list.length) await loadTask(list[0].id);
  };
  const loadTask = async (id: string) => {
    const next = await api("/api/audits/" + id);
    setTask(next);
    setReport(
      terminal(next.status)
        ? await api(`/api/audits/${id}/report`).catch(() => null)
        : null,
    );
  };
  useEffect(() => {
    loadShell().catch(console.error);
  }, []);
  useEffect(() => {
    if (!task || !["queued", "running"].includes(task.status)) return;
    const timer = setInterval(() => loadTask(task.id), 2500);
    return () => clearInterval(timer);
  }, [task?.id, task?.status]);
  const requests = task?.model_requests || [],
    paths = task?.path_sketches || [],
    packets = task?.validation_packets || [],
    validations = task?.path_validations || [],
    findings = report?.findings || [];
  const tokens = requests.reduce(
      (n: number, r: AnyRow) => n + (r.total_tokens || 0),
      0,
    ),
    seconds = requests.reduce(
      (n: number, r: AnyRow) => n + (r.seconds || 0),
      0,
    );
  const visibleTasks = useMemo(
    () =>
      tasks.filter((t) =>
        (t.objective + t.repository_id)
          .toLowerCase()
          .includes(query.toLowerCase()),
      ),
    [tasks, query],
  );
  const stageState = (id: string) => {
    const rows = (task?.stage_progress || []).filter(
      (x: AnyRow) => x.stage_id === id,
    );
    if (!rows.length) {
      const inferred: Record<string, boolean> = {
        scope_freeze: !!task?.scope,
        entry_prefetch: !!task?.agent_tasks?.length,
        path_probe: !!paths.length,
        validation_grouping: !!packets.length,
        evidence_supplement: !!task?.evidence_rounds?.length,
        path_validation: !!paths.length && validations.length === paths.length,
        report_assembly: task?.status === "needs_review",
      };
      return inferred[id] ? "done" : "legacy";
    }
    if (rows.some((x: AnyRow) => x.status === "running")) return "running";
    if (rows.some((x: AnyRow) => x.status === "failed")) return "failed";
    if (rows.every((x: AnyRow) => x.status === "completed")) return "done";
    return "queued";
  };
  const taskAction = async (kind: "cancel" | "resume" | "recover-stale") => {
    if (!task) return;
    setActionError("");
    try {
      const init: RequestInit = { method: "POST" };
      if (kind === "resume") {
        init.headers = { "Content-Type": "application/json" };
        init.body = JSON.stringify({
          max_steps: task.max_steps || 20,
          max_seconds: task.max_seconds || 900,
          allow_remote_code: !!task.allow_remote_code,
          allow_remote_config: !!task.allow_remote_config,
        });
      }
      const next = await api(`/api/audits/${task.id}/${kind}`, init);
      await loadTask(next.id || task.id);
      await loadShell();
    } catch (e: any) {
      setActionError(e.message);
    }
  };
  return (
    <div className="app">
      <aside>
        <div className="brand">
          <span>
            <ShieldCheck size={22} />
          </span>
          <b>
            SecVal<small>安全验证工作站</small>
          </b>
        </div>
        <nav>
          {[
            ["projects", "项目管理", FolderUp],
            ["overview", "运行视图", Activity],
            ["findings", "漏洞发现", ShieldCheck],
            ["evidence", "证据图谱", Workflow],
            ["traffic", "模型流量", Gauge],
            ["coverage", "覆盖与基准", Database],
          ].map(([id, label, Icon]: any) => (
            <button
              key={id}
              className={view === id ? "active" : ""}
              onClick={() => setView(id)}
            >
              <Icon />
              {label}
            </button>
          ))}
        </nav>
        <div className="engine">
          <i /> {settings.model || "审计模型"}
          <small>工具协议：{settings.tool_protocol || "—"}</small>
        </div>
      </aside>
      <main>
        <header>
          <h1>{viewTitles[view]}</h1>
          <label>
            <Search />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="搜索任务 / 项目 / CWE"
            />
          </label>
          <button className="icon" onClick={loadShell}>
            <RefreshCw />
          </button>
          <span className="avatar">安</span>
        </header>
        <div className="body">
          <section className="context">
            <div>
              <small>当前审计</small>
              <select
                value={task?.id || ""}
                onChange={(e) => loadTask(e.target.value)}
              >
                {visibleTasks.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.status} · {t.objective}
                  </option>
                ))}
              </select>
              <p>
                {task
                  ? `${task.repository_id} / ${(task.scope_paths || []).join(", ") || "全范围"} / #${task.id.slice(0, 8)}`
                  : "请选择任务"}
                {actionError && (
                  <span className="inlineError"> · {actionError}</span>
                )}
              </p>
            </div>
            <div className="actions">
              <span className={"state " + (task?.status || "")}>
                {task?.status || "未选择"}
              </span>
              {task && ["queued", "running"].includes(task.status) && (
                <button onClick={() => taskAction("cancel")}>取消任务</button>
              )}
              {task && terminal(task.status) && (
                <button onClick={() => taskAction("resume")}>续跑</button>
              )}
              {task?.lease_state === "expired" && (
                <button onClick={() => taskAction("recover-stale")}>
                  收口失联任务
                </button>
              )}
              <details>
                <summary>导出报告⌄</summary>
                <div>
                  <a href={task ? `/api/audits/${task.id}/report` : "#"}>
                    JSON 报告
                  </a>
                  <a href={task ? `/api/audits/${task.id}/report.md` : "#"}>
                    Markdown 报告
                  </a>
                </div>
              </details>
              <button className="primary" onClick={() => setModal(true)}>
                <Plus />
                新建审计
              </button>
            </div>
          </section>
          {view === "projects" ? (
            <ProjectManager onAuditReady={() => { loadShell(); setModal(true); }} />
          ) : view === "overview" ? (
            <>
              <section className="metrics">
                {[
                  ["正式发现", findings.length, "独立复核后"],
                  ["候选路径", paths.length, "来自 Path Probe"],
                  [
                    "已验证",
                    `${validations.length} / ${paths.length}`,
                    "逐路径结论",
                  ],
                  ["模型调用", requests.length, "供应商请求"],
                  ["Token", fmt(tokens), "输入与输出"],
                  ["模型耗时", seconds.toFixed(1) + "s", "累计请求时间"],
                ].map(([a, b, c]) => (
                  <article key={String(a)}>
                    <small>{a}</small>
                    <strong>{b}</strong>
                    <span>{c}</span>
                  </article>
                ))}
              </section>
              <Pipeline
                task={task}
                paths={paths}
                packets={packets}
                validations={validations}
                requests={requests}
                stageState={stageState}
              />
              <PathList paths={paths} validations={validations} />
            </>
          ) : (
            <Workspace
              view={view}
              task={task}
              report={report}
              paths={paths}
              validations={validations}
              requests={requests}
            />
          )}
        </div>
      </main>
      {modal && (
        <NewAudit
          onClose={() => setModal(false)}
          onCreated={(id) => {
            setModal(false);
            loadShell();
            loadTask(id);
          }}
        />
      )}
    </div>
  );
}

function NewAudit({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  const [repos, setRepos] = useState<AnyRow[]>([]),
    [repo, setRepo] = useState(""),
    [objective, setObjective] = useState(
      "审计外部入口、授权边界和高风险数据流，只报告证据支持的漏洞并记录反证。",
    ),
    [scope, setScope] = useState(""),
    [context, setContext] = useState(""),
    [steps, setSteps] = useState(20),
    [seconds, setSeconds] = useState(900),
    [agents, setAgents] = useState(3),
    [consent, setConsent] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  useEffect(() => {
    api("/api/repositories")
      .then((x) => {
        setRepos(x.repositories || []);
        if (x.repositories?.[0])
          setRepo(
            JSON.stringify({
              repository_id: x.repositories[0].repository_id,
              snapshot_id: x.repositories[0].snapshot_id,
            }),
          );
      })
      .catch((e) => setError(e.message));
  }, []);
  const submit = async () => {
    if (!repo) return;
    setBusy(true);
    setError("");
    try {
      const body = {
        ...JSON.parse(repo),
        objective,
        max_steps: steps,
        max_seconds: seconds,
        parallel_agents: agents,
        allow_remote_code: consent,
        security_context: context,
        supplied_threat_model: "",
        scope_paths: scope
          .split(/[,\n]/)
          .map((x) => x.trim())
          .filter(Boolean),
        independent_baseline: true,
        approved_config_paths: [],
        allow_remote_config: false,
      };
      const t = await api("/api/audits", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      onCreated(t.id);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="overlay">
      <div className="dialog">
        <h2>新建安全审计</h2>
        <p className="hint">
          配置代码范围、调查目标和执行预算。创建后可在运行视图观察完整阶段。
        </p>
        <label>
          仓库 / 快照
          <select value={repo} onChange={(e) => setRepo(e.target.value)}>
            {repos.map((r) => (
              <option
                key={r.repository_id + r.snapshot_id}
                value={JSON.stringify({
                  repository_id: r.repository_id,
                  snapshot_id: r.snapshot_id,
                })}
              >
                {r.repository_id} / {r.snapshot_id}
              </option>
            ))}
          </select>
        </label>
        <label>
          审计目标
          <textarea
            value={objective}
            onChange={(e) => setObjective(e.target.value)}
          />
        </label>
        <div className="formGrid">
          <label>
            范围路径（逗号或换行）
            <input
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              placeholder="modules/sys, modules/cms"
            />
          </label>
          <label>
            安全上下文
            <input
              value={context}
              onChange={(e) => setContext(e.target.value)}
              placeholder="信任边界、部署约束…"
            />
          </label>
          <label>
            最大模型轮次
            <input
              type="number"
              min="1"
              max="300"
              value={steps}
              onChange={(e) => setSteps(+e.target.value)}
            />
          </label>
          <label>
            最长时间（秒）
            <input
              type="number"
              min="30"
              max="3600"
              value={seconds}
              onChange={(e) => setSeconds(+e.target.value)}
            />
          </label>
          <label>
            并行调查面
            <select value={agents} onChange={(e) => setAgents(+e.target.value)}>
              <option value="1">1</option>
              <option value="2">2</option>
              <option value="3">3</option>
              <option value="4">4</option>
            </select>
          </label>
        </div>
        <label className="check">
          <input
            type="checkbox"
            checked={consent}
            onChange={(e) => setConsent(e.target.checked)}
          />
          允许向审计模型发送候选源码片段
        </label>
        {error && <p className="error">{error}</p>}
        <footer>
          <button onClick={onClose}>取消</button>
          <button
            className="primary"
            disabled={busy || !repo || objective.length < 5}
            onClick={submit}
          >
            {busy ? "正在创建…" : "开始审计"}
          </button>
        </footer>
      </div>
    </div>
  );
}

function Pipeline({
  task,
  paths,
  packets,
  validations,
  requests,
  stageState,
}: AnyRow) {
  return (
    <section className="panel">
      <div className="panelTitle">
        <b>审计流水线</b>
        <span>{task?.stop_reason || "实时阶段与批量调查包"}</span>
      </div>
      <div className="stages">
        {stages.map(([id, label]) => (
          <div key={id} className={stageState(id)}>
            <i />
            <b>{label}</b>
            <small>{stageState(id)}</small>
          </div>
        ))}
      </div>
      <div className="packets">
        {packets.length ? (
          packets.slice(0, 8).map((p: AnyRow, i: number) => (
            <div className="packet" key={p.id || i}>
              <b>
                {p.security_surface || p.surface || `调查包 ${i + 1}`}
                <small>{p.status || "已分组"}</small>
              </b>
              <span>
                <em>候选路径</em>
                {(p.path_ids || p.paths || []).length || paths.length}
              </span>
              <i>→</i>
              <span>
                <em>补充证据</em>
                {(p.evidence_ids || []).length}
              </span>
              <i>→</i>
              <span>
                <em>验证结论</em>
                {validations.length}
              </span>
              <small>{requests.length} 次调用</small>
            </div>
          ))
        ) : (
          <div className="empty">
            暂无验证分组；Path Probe 产出路径后会在这里按安全面汇总。
          </div>
        )}
      </div>
    </section>
  );
}

function Traffic({ requests }: { requests: AnyRow[] }) {
  const max = Math.max(1, ...requests.map((r) => r.total_tokens || 0));
  return (
    <section className="panel">
      <div className="panelTitle">
        <b>模型调用与流量</b>
        <span>
          {fmt(requests.reduce((n, r) => n + (r.total_tokens || 0), 0))} tokens
        </span>
      </div>
      {requests.length ? (
        requests
          .slice()
          .reverse()
          .slice(0, 12)
          .map((r, i) => (
            <details className="request" key={r.id || i}>
              <summary>
                <b>#{requests.length - i}</b>
                <span>{r.purpose || r.stage || r.model || "模型请求"}</span>
                <span>
                  {fmt(r.total_tokens || 0)} ·{" "}
                  {Number(r.seconds || 0).toFixed(1)}s
                </span>
                <i
                  style={{
                    width: `${Math.max(3, ((r.total_tokens || 0) / max) * 100)}%`,
                  }}
                />
              </summary>
              <pre>{JSON.stringify(r, null, 2)}</pre>
            </details>
          ))
      ) : (
        <div className="empty">暂无模型请求记录</div>
      )}
    </section>
  );
}

function PathList({
  paths,
  validations,
}: {
  paths: AnyRow[];
  validations: AnyRow[];
}) {
  return (
    <section className="panel">
      <div className="panelTitle">
        <b>候选攻击路径</b>
        <span>
          {validations.length} / {paths.length} 已验证
        </span>
      </div>
      {paths.length ? (
        paths.slice(0, 12).map((p, i) => {
          const v = validations.find(
            (x) => (x.path_id || x.id) === (p.path_id || p.id),
          );
          return (
            <details className="pathDetail" key={p.path_id || p.id || i}>
              <summary>
                <strong>
                  {p.candidate_type ||
                    p.vulnerability_type ||
                    p.surface ||
                    p.security_surface ||
                    p.category ||
                    "待分类路径"}
                </strong>
                <span>
                  {p.source || p.entry || p.entry_point || "入口待确认"}
                </span>
                <i>→</i>
                <span>{p.sink || p.dangerous_operation || "汇点待确认"}</span>
                <b className={v ? "ok" : "pending"}>
                  {v?.outcome || v?.verdict || v?.status || "待验证"}
                </b>
              </summary>
              <div className="detailBody">
                <p>
                  {p.hypothesis ||
                    p.summary ||
                    p.rationale ||
                    p.description ||
                    "暂无路径摘要"}
                </p>
                {p.hops && <pre>{JSON.stringify(p.hops, null, 2)}</pre>}
                {v && <pre>{JSON.stringify(v, null, 2)}</pre>}
              </div>
            </details>
          );
        })
      ) : (
        <div className="empty">尚未形成候选攻击路径</div>
      )}
    </section>
  );
}

function Workspace({
  view,
  task,
  report,
  paths,
  validations,
  requests,
}: AnyRow) {
  if (!task) return <div className="empty">请选择审计任务</div>;
  if (view === "findings") {
    const fs = report?.findings || [];
    const reviews = task.independent_reviews || report?.independentReviews || [];
    const pending = reviews.filter((row: AnyRow) => row.outcome !== "supported");
    return (
      <div className="workspace">
        <PathList paths={paths} validations={validations} />
        {pending.length > 0 && <section className="panel">
          <div className="panelTitle">
            <b>待复核候选</b>
            <span>{pending.length} 条 · 不会因复核失败而隐藏</span>
          </div>
          {pending.map((row: AnyRow, i: number) => {
            const investigation = (task.investigations || []).find(
              (item: AnyRow) => item.id === row.investigation_id
            );
            return <article className="finding" key={row.investigation_id || i}>
              <div><span className="severity medium">{row.outcome || "pending"}</span>
                <strong>{investigation?.question || row.investigation_id || `候选 ${i + 1}`}</strong></div>
              <p>{row.error || row.assessment || "独立复核尚未完成"}</p>
            </article>;
          })}
        </section>}
        <section className="panel">
          <div className="panelTitle">
            <b>正式发现</b>
            <span>{fs.length} 条</span>
          </div>
          {fs.length ? (
            fs.map((f: AnyRow, i: number) => {
              const severity = typeof f.severity === "object"
                ? f.severity?.level || "unknown"
                : f.severity || "unknown";
              const title = f.title || f.detail?.title || f.vulnerability_type || `发现 ${i + 1}`;
              const summary = f.summary || f.detail?.summary || f.description || f.rootCause?.summary;
              return <article className="finding" key={f.id || f.findingId || i}>
                <div>
                  <span
                    className={`severity ${String(severity).toLowerCase()}`}
                  >
                    {severity}
                  </span>
                  <strong>{title}</strong>
                </div>
                <p>{summary}</p>
                <pre>{JSON.stringify(f, null, 2)}</pre>
              </article>
            })
          ) : (
            <div className="empty">
              当前报告没有通过复核的正式漏洞；候选路径仍可在上方查看。
            </div>
          )}
        </section>
      </div>
    );
  }
  if (view === "traffic")
    return <ModelHistory task={task} requests={requests} />;
  if (view === "evidence") {
    const evidence = task.evidence || {};
    const rows = Array.isArray(evidence)
      ? evidence
      : Object.entries(evidence).map(([id, value]) => ({
          id,
          ...(value as AnyRow),
        }));
    return (
      <div className="workspace">
        <PathList paths={paths} validations={validations} />
        <section className="panel">
          <div className="panelTitle">
            <b>证据账本</b>
            <span>{rows.length} 个证据对象 · 仅按需展开</span>
          </div>
          {rows.length ? (
            rows.map((e: AnyRow, i: number) => (
              <details className="record" key={e.id || i}>
                <summary>
                  <b>{e.id || e.evidence_id || `证据 ${i + 1}`}</b>
                  <span>{e.path || e.file_path || e.kind || "证据片段"}</span>
                </summary>
                <pre>{JSON.stringify(e, null, 2)}</pre>
              </details>
            ))
          ) : (
            <div className="empty">暂无持久化证据对象</div>
          )}
        </section>
      </div>
    );
  }
  const coverage = report?.coverage || {},
    files = coverage.files || {},
    completion = report?.completion || {},
    budget = report?.budget || {};
  return (
    <div className="workspace">
      <section className="metrics compact">
        {[
          [
            "已审文件",
            (files.reviewed_static || []).length ||
              (task.file_reviews || []).length,
          ],
          ["剩余文件", (files.remaining || []).length],
          ["排除文件", (files.excluded || []).length],
          [
            "模型轮次",
            `${requests.length} / ${budget.maxModelCalls || task.max_steps || "—"}`,
          ],
        ].map(([a, b]) => (
          <article key={String(a)}>
            <small>{a}</small>
            <strong>{b}</strong>
          </article>
        ))}
      </section>
      <section className="panel">
        <div className="panelTitle">
          <b>覆盖、预算与停止条件</b>
          <span>{completion.state || task.status}</span>
        </div>
        <div className="twoCol">
          <Record title="覆盖详情" value={coverage} />
          <Record title="完成度" value={completion} />
          <Record title="预算" value={budget} />
          <Record
            title="未知项与限制"
            value={{
              unknowns: report?.unknowns,
              limitations: report?.limitations,
              exclusions: report?.exclusions,
              deferred: task.deferred_items,
            }}
          />
        </div>
      </section>
    </div>
  );
}

function Record({ title, value }: { title: string; value: any }) {
  return (
    <article className="recordCard">
      <b>{title}</b>
      <pre>{JSON.stringify(value || {}, null, 2)}</pre>
    </article>
  );
}

function ModelHistory({
  task,
  requests,
}: {
  task: AnyRow;
  requests: AnyRow[];
}) {
  const [selected, setSelected] = useState(0),
    [filter, setFilter] = useState(""),
    [tab, setTab] = useState<"pretty" | "raw">("pretty");
  const rows = requests
    .map((r, i) => ({ ...r, _index: i }))
    .filter((r) =>
      `${r.call} ${r.agent_id} ${r.phase} ${r.status}`
        .toLowerCase()
        .includes(filter.toLowerCase()),
    );
  const current = requests[selected] || rows[0];
  useEffect(() => {
    if (selected >= requests.length)
      setSelected(Math.max(0, requests.length - 1));
  }, [requests.length]);
  const requestView = current?.request_messages ||
    (current ? {
        method: "POST",
        endpoint: "/v1/chat/completions",
        phase: current.phase,
        agent_id: current.agent_id,
        input_characters: current.input_characters,
        prompt_tokens: current.prompt_tokens,
        notice: "该历史调用发生在完整流量留存启用之前",
      }
    : {});
  const responseView = current?.response_action ||
    (current ? {
        status: current.status,
        completion_tokens: current.completion_tokens,
        total_tokens: current.total_tokens,
        reasoning_characters: current.reasoning_characters,
        content_characters: current.content_characters,
        seconds: current.seconds,
        first_data_ms: current.first_data_ms,
        code: current.code,
        notice: "该历史调用发生在完整流量留存启用之前",
      }
    : {});
  return (
    <div className="workspace history">
      <section className="metrics compact">
        {[
          ["请求", requests.length],
          [
            "输入 Token",
            fmt(requests.reduce((n, r) => n + (r.prompt_tokens || 0), 0)),
          ],
          [
            "输出 Token",
            fmt(requests.reduce((n, r) => n + (r.completion_tokens || 0), 0)),
          ],
          [
            "总耗时",
            requests
              .reduce((n, r) => n + Number(r.seconds || 0), 0)
              .toFixed(1) + "s",
          ],
        ].map(([a, b]) => (
          <article key={String(a)}>
            <small>{a}</small>
            <strong>{b}</strong>
          </article>
        ))}
      </section>
      <section className="panel historyPanel">
        <div className="historyToolbar">
          <b>模型 HTTP 历史记录</b>
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="筛选 Agent / 阶段 / 状态"
          />
          <span>
            {rows.length} / {requests.length}
          </span>
        </div>
        <div className="historyTable">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Agent / 调查包</th>
                <th>阶段</th>
                <th>状态</th>
                <th>输入字符</th>
                <th>Prompt</th>
                <th>Completion</th>
                <th>总 Token</th>
                <th>耗时</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr
                  key={r._index}
                  className={selected === r._index ? "selected" : ""}
                  onClick={() => setSelected(r._index)}
                >
                  <td>{r.call || r._index + 1}</td>
                  <td>{r.agent_id || "—"}</td>
                  <td>{r.phase || "—"}</td>
                  <td>
                    <span
                      className={`httpStatus ${r.status === "response_returned" ? "success" : "warning"}`}
                    >
                      {r.status || "—"}
                    </span>
                  </td>
                  <td>{fmt(r.input_characters || 0)}</td>
                  <td>{fmt(r.prompt_tokens || 0)}</td>
                  <td>{fmt(r.completion_tokens || 0)}</td>
                  <td>{fmt(r.total_tokens || 0)}</td>
                  <td>{Number(r.seconds || 0).toFixed(1)}s</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && <div className="empty">没有匹配的模型请求</div>}
        </div>
        {current && (
          <div className="exchange">
            <div className="exchangeHead">
              <b>调用 #{current.call || selected + 1}</b>
              <span>POST /v1/chat/completions</span>
              <div>
                <button
                  className={tab === "pretty" ? "active" : ""}
                  onClick={() => setTab("pretty")}
                >
                  Pretty
                </button>
                <button
                  className={tab === "raw" ? "active" : ""}
                  onClick={() => setTab("raw")}
                >
                  Raw
                </button>
              </div>
            </div>
            <div className="exchangeSplit">
              <section>
                <h3>Request</h3>
                {tab === "pretty" ? (
                  <KeyValues value={requestView} />
                ) : (
                  <pre>{JSON.stringify(requestView, null, 2)}</pre>
                )}
              </section>
              <section>
                <h3>Response</h3>
                {tab === "pretty" ? (
                  <KeyValues value={responseView} />
                ) : (
                  <pre>
                    {JSON.stringify(responseView, null, 2)}
                  </pre>
                )}
              </section>
            </div>
          </div>
        )}
      </section>
      <p className="retentionNote">
        新调用会保存完整请求消息和结构化响应，但不会保存 API 密钥及供应商私有推理正文。旧任务只能展示当时已经记录的元数据。
      </p>
    </div>
  );
}

function KeyValues({ value }: { value: AnyRow }) {
  return (
    <div className="keyValues">
      {Object.entries(value).map(([k, v]) => (
        <div key={k}>
          <span>{k}</span>
          <code>{v == null ? "—" : String(v)}</code>
        </div>
      ))}
    </div>
  );
}
