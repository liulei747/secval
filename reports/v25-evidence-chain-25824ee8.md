# V25 存储型 XSS 证据链

## 1. 路径草稿

```json
{
  "surface": "injection",
  "candidate_type": "xss",
  "entry": "GET /api/pages/{pageId}",
  "source": "客户端可控的@PathVariable pageId",
  "hops": [
    "PageController.page 将 pageId 传给 renderPage",
    "renderPage 读取对应页面内容并渲染",
    "以 TEXT_HTML 返回渲染结果"
  ],
  "sink": "HTML 响应中的存储型 XSS / 模板注入",
  "control": "存储内容输出编码与 pageId 路径校验，控制器未体现防护",
  "hypothesis": "renderPage 渲染用户可控页面内容并以 TEXT_HTML 返回，存在存储型 XSS 或模板注入风险。",
  "needs": [
    {
      "kind": "symbol_definition",
      "target": "PageService.renderPage",
      "reason": "确认渲染方式及是否进行输出编码",
      "required_for": "xss"
    },
    {
      "kind": "template_resolution",
      "target": "renderPage 的渲染流程",
      "reason": "确认页面内容是否经过转义",
      "required_for": "xss"
    }
  ],
  "evidence_ids": [
    "file:00911d3d7aec5c245c62f6e861296151825b31e2527d1e729d508ae1f74b2300:0:1578"
  ],
  "id": "agent-3:path-6",
  "status": "supported",
  "source_id": "agent-3"
}
```

## 2. 路径验证结论

```json
{
  "path_id": "agent-3:path-6",
  "outcome": "supported",
  "assessment": "renderPage拼接page中TITLE与BODY到HTML返回，无输出编码，存储型XSS成立",
  "counterevidence": "无",
  "limitations": [],
  "evidence_ids": [
    "file:00911d3d7aec5c245c62f6e861296151825b31e2527d1e729d508ae1f74b2300:0:1578",
    "file:0577ad1023f5c637dcdfa1a54f5ad51f5779ff5077e02e3d9bb4f31e64c97732:0:1010"
  ],
  "packet_id": "validation:0f8724a1fb6ba845"
}
```

## 3. 候选详情

```json
{
  "title": "xss：GET /api/pages/{pageId}",
  "summary": "renderPage 渲染用户可控页面内容并以 TEXT_HTML 返回，存在存储型 XSS 或模板注入风险。",
  "rootCause": {
    "summary": "renderPage拼接page中TITLE与BODY到HTML返回，无输出编码，存储型XSS成立",
    "evidenceRefs": [
      "file:00911d3d7aec5c245c62f6e861296151825b31e2527d1e729d508ae1f74b2300:0:1578",
      "file:0577ad1023f5c637dcdfa1a54f5ad51f5779ff5077e02e3d9bb4f31e64c97732:0:1010"
    ]
  },
  "attackPath": {
    "summary": "renderPage 渲染用户可控页面内容并以 TEXT_HTML 返回，存在存储型 XSS 或模板注入风险。",
    "dataflow": {
      "summary": "输入沿已验证路径到达安全敏感操作",
      "source": "客户端可控的@PathVariable pageId",
      "transformations": [
        "PageController.page 将 pageId 传给 renderPage",
        "renderPage 读取对应页面内容并渲染",
        "以 TEXT_HTML 返回渲染结果"
      ],
      "sink": "HTML 响应中的存储型 XSS / 模板注入",
      "outcome": "renderPage 渲染用户可控页面内容并以 TEXT_HTML 返回，存在存储型 XSS 或模板注入风险。",
      "evidenceRefs": [
        "file:00911d3d7aec5c245c62f6e861296151825b31e2527d1e729d508ae1f74b2300:0:1578",
        "file:0577ad1023f5c637dcdfa1a54f5ad51f5779ff5077e02e3d9bb4f31e64c97732:0:1010"
      ]
    },
    "reachability": {
      "summary": "攻击者可从GET /api/pages/{pageId}触发路径",
      "attacker": "客户端可控的@PathVariable pageId",
      "entrypoint": "GET /api/pages/{pageId}",
      "preconditions": [
        "满足验证记录中的攻击前提"
      ],
      "outcome": "renderPage 渲染用户可控页面内容并以 TEXT_HTML 返回，存在存储型 XSS 或模板注入风险。",
      "evidenceRefs": [
        "file:00911d3d7aec5c245c62f6e861296151825b31e2527d1e729d508ae1f74b2300:0:1578",
        "file:0577ad1023f5c637dcdfa1a54f5ad51f5779ff5077e02e3d9bb4f31e64c97732:0:1010"
      ]
    },
    "impact": {
      "level": "medium",
      "rationale": "HTML 响应中的存储型 XSS / 模板注入"
    },
    "likelihood": {
      "level": "medium",
      "rationale": "renderPage拼接page中TITLE与BODY到HTML返回，无输出编码，存储型XSS成立"
    },
    "limitations": [
      "仅完成静态源码验证，未执行动态利用"
    ],
    "evidenceRefs": [
      "file:00911d3d7aec5c245c62f6e861296151825b31e2527d1e729d508ae1f74b2300:0:1578",
      "file:0577ad1023f5c637dcdfa1a54f5ad51f5779ff5077e02e3d9bb4f31e64c97732:0:1010"
    ]
  },
  "severity": {
    "level": "medium",
    "rationale": "renderPage 渲染用户可控页面内容并以 TEXT_HTML 返回，存在存储型 XSS 或模板注入风险。"
  },
  "confidence": {
    "level": "high",
    "rationale": "独立路径验证判定supported"
  },
  "remediation": "在GET /api/pages/{pageId}到HTML 响应中的存储型 XSS / 模板注入之间实施并集中复用存储内容输出编码与 pageId 路径校验，控制器未体现防护。",
  "remediationTests": [
    "增加未授权或恶意输入被拒绝的回归测试"
  ],
  "preventiveControls": [
    "存储内容输出编码与 pageId 路径校验，控制器未体现防护"
  ],
  "evidenceNotes": [
    {
      "evidence_id": "file:00911d3d7aec5c245c62f6e861296151825b31e2527d1e729d508ae1f74b2300:0:1578",
      "role": "root_control",
      "explanation": "路径验证引用的源码证据"
    },
    {
      "evidence_id": "file:0577ad1023f5c637dcdfa1a54f5ad51f5779ff5077e02e3d9bb4f31e64c97732:0:1010",
      "role": "propagation",
      "explanation": "路径验证引用的源码证据"
    }
  ],
  "ruleId": "xss",
  "taxonomy": {
    "category": "injection",
    "cwe": [
      "CWE-79"
    ]
  },
  "root_control": "file:00911d3d7aec5c245c62f6e861296151825b31e2527d1e729d508ae1f74b2300:0:1578",
  "investigation_id": "investigation-5",
  "id": "detail-5",
  "status": "needs_review",
  "worker_candidate_id": "agent-3:path-6:finding-1"
}
```

## 4. 独立复核结论

```json
{
  "investigation_id": "investigation-5",
  "outcome": "inconclusive",
  "assessment": "由给定源码可确认：PageController 中 GET /{pageId} 以 produces=TEXT_HTML 调用 pageService.renderPage(pageId)，text/html 响应由浏览器按 HTML 渲染；PageService.renderPage 将 pageRepository.findById 返回的 TITLE 与 BODY 直接字符串拼接进 HTML 响应，无任何输出编码，而同一文件 buildSearchText 使用了 HtmlUtils.htmlEscape，说明编码手段存在但 renderPage 未采用——sink 端无防护成立。然而存储型 XSS 的完整链路未被证据包证明：PageRequest DTO 字段（是否含 TITLE/BODY）与 PageRepository 的 save/findById 实现均不在所给证据中，无法独立证明攻击者可控的请求体内容确实被持久化并原样回读；POST/GET 端点是否存在认证或拦截亦无证据。'模板注入'主张与代码不符：renderPage 为普通字符串拼接，未引用任何模板引擎。故 sink 缺陷有依据，但存储内容可控性与完整攻击链缺少决定性证明，判定 inconclusive。",
  "counterevidence": "无有效防护反证该漏洞假设：renderPage 输出未编码，且 buildSearchText 的 HtmlUtils.htmlEscape 对比恰证明编码能力存在却未用于该路径。阻碍 supported 的是漏洞假设未证明环节：①PageRequest 字段未示出，无法证明 TITLE/BODY 由攻击者请求体控制；②PageRepository.findById/save 实现缺失，存储→回读数据流未证明；③端点认证/授权状态未知，不能排除仅特权用户可写页面；④模板注入无模板引擎依据，与普通拼接代码矛盾。",
  "limitations": [
    "证据包不含 PageRequest DTO 源码，无法证明其含 TITLE/BODY 字段或由请求体直接控制",
    "证据包不含 PageRepository 实现，save/findById 的持久化与回读语义未证明，存储型链路缺关键一环",
    "POST /api/pages 与 GET /api/pages/{pageId} 的认证/授权（过滤器、拦截器、security 配置）不在证据中，无法排除端点受限",
    "无模板引擎相关证据，'模板注入'分类与所见的普通字符串拼接代码不符",
    "未进行动态复现，且批准配置 application.yml 内容未提供，无法核实运行期防护"
  ],
  "evidence_ids": [
    "file:00911d3d7aec5c245c62f6e861296151825b31e2527d1e729d508ae1f74b2300:0:1578",
    "file:0577ad1023f5c637dcdfa1a54f5ad51f5779ff5077e02e3d9bb4f31e64c97732:0:1010"
  ],
  "method": "independent_context_packet_review",
  "input_sha256": "3f695040f6794257be6d55b08f2c92ad283db7dd7d1b895138e9658e9f3c8d06",
  "input_identity_version": 1,
  "evidence_fingerprints": {
    "file:00911d3d7aec5c245c62f6e861296151825b31e2527d1e729d508ae1f74b2300:0:1578": "a406d1aed5861b6a7e78b1e60840b462735c028c61f16eeb4f1dc2f4c728be29",
    "file:0577ad1023f5c637dcdfa1a54f5ad51f5779ff5077e02e3d9bb4f31e64c97732:0:1010": "ce37daacef1b50f4112f82e435908bc0e418031f11572da6cc2f0017b8e1206d"
  },
  "detail_sha256": "5015bff1bb48b57724a422799498c76b7762f197cc7b03699b73819f8bdb84c3",
  "independent_source_exploration": false,
  "additional_evidence_reads": 0,
  "dynamic_validation": false,
  "attempts": 1,
  "reused": true
}
```

## 5. 独立复核实际收到的源码证据

### file:00911d3d7aec5c245c62f6e861296151825b31e2527d1e729d508ae1f74b2300:0:1578

文件：`src/main/java/com/sinkspring/bench/controller/PageController.java`，行 1–44

```java
package com.sinkspring.bench.controller;

import com.sinkspring.bench.dto.PageRequest;
import com.sinkspring.bench.service.PageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/pages")
public class PageController {

    @Autowired
    private PageService pageService;

    @GetMapping(value = "/search", produces = MediaType.TEXT_HTML_VALUE)
    public String search(@RequestParam String query) {
        return pageService.buildSearchPage(query);
    }

    @PostMapping
    public Map<String, String> save(@RequestBody PageRequest request) {
        pageService.savePage(request);
        return Map.of("pageId", request.getPageId());
    }

    @GetMapping(value = "/{pageId}", produces = MediaType.TEXT_HTML_VALUE)
    public String page(@PathVariable String pageId) {
        return pageService.renderPage(pageId);
    }

    @GetMapping(value = "/search/text", produces = MediaType.TEXT_PLAIN_VALUE)
    public String searchText(@RequestParam String query) {
        return pageService.buildSearchText(query);
    }
}

```

### file:0577ad1023f5c637dcdfa1a54f5ad51f5779ff5077e02e3d9bb4f31e64c97732:0:1010

文件：`src/main/java/com/sinkspring/bench/service/PageService.java`，行 1–34

```java
package com.sinkspring.bench.service;

import com.sinkspring.bench.dao.PageRepository;
import com.sinkspring.bench.dto.PageRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.util.HtmlUtils;

import java.util.Map;

@Service
public class PageService {

    @Autowired
    private PageRepository pageRepository;

    public String buildSearchPage(String query) {
        return "<html><body><h1>Search</h1><p>Results for " + query + "</p></body></html>";
    }

    public void savePage(PageRequest request) {
        pageRepository.save(request);
    }

    public String renderPage(String pageId) {
        Map<String, Object> page = pageRepository.findById(pageId);
        return "<html><body><h1>" + page.get("TITLE") + "</h1>"
                + page.get("BODY") + "</body></html>";
    }

    public String buildSearchText(String query) {
        return "Results for " + HtmlUtils.htmlEscape(query);
    }
}

```

## 6. 核对结论

路径验证记录的 `outcome` 为 `supported`。候选详情关联 `investigation-5`。独立复核记录的 `outcome` 为 `inconclusive`，并明确列出缺少 `PageRequest` DTO、`PageRepository` 实现及端点安全配置；其 `additional_evidence_reads` 为 0、`independent_source_exploration` 为 false。
