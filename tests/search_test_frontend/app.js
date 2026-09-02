const apiAddress = "http://127.0.0.1:8000";

const indexForm = document.querySelector("#indexForm");
const uploadForm = document.querySelector("#uploadForm");
const zipUploadForm = document.querySelector("#zipUploadForm");
const searchForm = document.querySelector("#searchForm");
const uploadButton = document.querySelector("#uploadButton");
const zipUploadButton = document.querySelector("#zipUploadButton");
const indexButton = document.querySelector("#indexButton");
const searchButton = document.querySelector("#searchButton");
const indexStatus = document.querySelector("#indexStatus");
const uploadStatus = document.querySelector("#uploadStatus");
const searchStatus = document.querySelector("#searchStatus");
const resultSummary = document.querySelector("#resultSummary");
const resultCards = document.querySelector("#resultCards");
const rawJson = document.querySelector("#rawJson");

document.querySelector("#apiAddress").textContent = apiAddress;
document.querySelector("#checkHealthButton").addEventListener("click", checkHealth);
indexForm.addEventListener("submit", indexRepository);
uploadForm.addEventListener("submit", uploadRepository);
zipUploadForm.addEventListener("submit", uploadRepositoryZip);
searchForm.addEventListener("submit", searchCode);
document.querySelector("#repositoryFiles").addEventListener("change", showSelectedFiles);

for (const button of document.querySelectorAll(".view-button")) {
    button.addEventListener("click", changeResultView);
}

async function checkHealth() {
    const healthDot = document.querySelector("#healthDot");
    const healthText = document.querySelector("#healthText");

    healthDot.className = "health-dot";
    healthText.textContent = "正在检查";

    try {
        const response = await fetch("/api/health");
        const body = await readResponseBody(response);
        ensureSuccessfulResponse(response, body);

        healthDot.className = "health-dot success";
        healthText.textContent = [
            `服务正常 · OpenSearch ${body.open_search} · Qdrant ${body.qdrant}`,
            `Embedding ${body.embedding_provider} · ${body.embedding_model}`,
        ].join(" · ");
    } catch (error) {
        healthDot.className = "health-dot error";
        healthText.textContent = `连接失败：${error.message}`;
    }
}

async function indexRepository(event) {
    event.preventDefault();
    setWorkingState(indexButton, indexStatus, true, "正在扫描、切分并写入搜索索引……");

    const requestBody = {
        repository_id: valueOf("repositoryId"),
        repository_name: valueOf("repositoryName"),
        repository_path: valueOf("repositoryPath"),
        snapshot_id: valueOf("snapshotId"),
        version: valueOf("version"),
    };

    try {
        const response = await sendJson("/api/repositories/index", requestBody);
        indexStatus.className = "status-box success";
        indexStatus.textContent = [
            `入库完成，批次 ${response.index_run_id}`,
            `扫描 ${response.total_files} 个文件，成功 ${response.successful_files} 个，失败 ${response.failed_files} 个。`,
            `生成 ${response.generated_chunks} 个代码块，写入文本 ${response.saved_chunks} 个、向量 ${response.saved_vectors} 个，清理旧块 ${response.deleted_chunks} 个。`,
        ].join("\n");

        // 搜索必须使用本次入库相同的仓库 ID 和快照 ID。
        searchStatus.className = "status-box empty";
        searchStatus.textContent = "入库已完成，可以模拟 LLM 搜索。";
    } catch (error) {
        showError(indexStatus, error);
    } finally {
        indexButton.disabled = false;
        indexButton.textContent = "2. 建立搜索索引";
    }
}

async function uploadRepository(event) {
    event.preventDefault();
    const selectedFiles = document.querySelector("#repositoryFiles").files;
    if (selectedFiles.length === 0) {
        showError(uploadStatus, new Error("请先选择一个本机代码目录"));
        return;
    }

    setWorkingState(uploadButton, uploadStatus, true, `正在上传 ${selectedFiles.length} 个文件……`);
    const formData = new FormData();
    formData.append("repository_directory", valueOf("repositoryPath"));
    formData.append("replace_existing", document.querySelector("#replaceExisting").checked);

    for (const file of selectedFiles) {
        // webkitRelativePath 保存了文件在所选目录中的层级。
        // 去掉最外层目录名，避免服务端出现 project/project/src 这种重复目录。
        const relativePath = removeSelectedRoot(file.webkitRelativePath || file.name);
        formData.append("files", file, relativePath);
    }

    try {
        const response = await sendForm("/api/repositories/upload", formData);
        document.querySelector("#repositoryPath").value = response.repository_path;
        uploadStatus.className = "status-box success";
        uploadStatus.textContent = [
            `上传完成：${response.repository_path}`,
            `${response.uploaded_files} 个文件，共 ${formatBytes(response.uploaded_bytes)}。`,
            response.replaced_existing ? "已替换原有同名目录。" : "这是一个新目录。",
            "下一步请点击“建立搜索索引”。",
        ].join("\n");
    } catch (error) {
        showError(uploadStatus, error);
    } finally {
        uploadButton.disabled = false;
        uploadButton.textContent = "1A. 上传代码目录";
    }
}

async function uploadRepositoryZip(event) {
    event.preventDefault();
    const zipFile = document.querySelector("#repositoryZip").files[0];
    if (!zipFile) {
        showError(uploadStatus, new Error("请先选择一个 ZIP 压缩包"));
        return;
    }

    setWorkingState(
        zipUploadButton,
        uploadStatus,
        true,
        `正在上传并解压 ${zipFile.name}……`,
    );
    const formData = new FormData();
    formData.append("repository_directory", valueOf("repositoryPath"));
    formData.append("replace_existing", document.querySelector("#replaceExisting").checked);
    formData.append("zip_file", zipFile);

    try {
        const response = await sendForm("/api/repositories/upload-zip", formData);
        document.querySelector("#repositoryPath").value = response.repository_path;
        uploadStatus.className = "status-box success";
        uploadStatus.textContent = [
            `ZIP 上传并解压完成：${response.repository_path}`,
            `${response.uploaded_files} 个文件，解压后 ${formatBytes(response.uploaded_bytes)}。`,
            response.replaced_existing ? "已替换原有同名目录。" : "这是一个新目录。",
            "下一步请点击“建立搜索索引”。",
        ].join("\n");
    } catch (error) {
        showError(uploadStatus, error);
    } finally {
        zipUploadButton.disabled = false;
        zipUploadButton.textContent = "1B. 上传 ZIP 压缩包";
    }
}

async function searchCode(event) {
    event.preventDefault();
    setWorkingState(searchButton, searchStatus, true, "LLM 正在调用混合搜索接口……");

    const requestBody = {
        text: valueOf("question"),
        repository_ids: [valueOf("repositoryId")],
        snapshot_ids: [valueOf("snapshotId")],
        top_k: Number(valueOf("topK")),
        language: optionalValueOf("language"),
        path_prefix: optionalValueOf("pathPrefix"),
        chunk_type: optionalValueOf("chunkType"),
    };

    try {
        const response = await sendJson("/api/search", requestBody);
        searchStatus.className = "status-box success";
        searchStatus.textContent = `搜索完成，LLM 收到 ${response.result_count} 个代码块。`;
        showSearchResults(response);
    } catch (error) {
        showError(searchStatus, error);
        clearSearchResults("搜索失败，没有可交给 LLM 的上下文。");
    } finally {
        searchButton.disabled = false;
        searchButton.textContent = "模拟 LLM 搜索";
    }
}

async function sendJson(path, requestBody) {
    const response = await fetch(path, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(requestBody),
    });
    const responseBody = await readResponseBody(response);
    ensureSuccessfulResponse(response, responseBody);
    return responseBody;
}

async function sendForm(path, formData) {
    const response = await fetch(path, {
        method: "POST",
        body: formData,
    });
    const responseBody = await readResponseBody(response);
    ensureSuccessfulResponse(response, responseBody);
    return responseBody;
}

async function readResponseBody(response) {
    const responseText = await response.text();
    if (!responseText) {
        return {};
    }

    try {
        return JSON.parse(responseText);
    } catch {
        throw new Error(`服务返回的不是 JSON（HTTP ${response.status}）`);
    }
}

function ensureSuccessfulResponse(response, responseBody) {
    if (response.ok) {
        return;
    }

    const detail = responseBody.detail;
    if (Array.isArray(detail)) {
        const messages = detail.map((item) => item.msg).join("；");
        throw new Error(`HTTP ${response.status}：${messages}`);
    }
    throw new Error(`HTTP ${response.status}：${detail || "请求失败"}`);
}

function showSearchResults(response) {
    resultCards.replaceChildren();
    rawJson.textContent = JSON.stringify(response, null, 2);
    resultSummary.textContent = `问题“${valueOf("question")}”返回 ${response.result_count} 条结果。下面这些代码块就是模拟 LLM 得到的上下文。`;

    if (response.results.length === 0) {
        resultSummary.textContent += " 当前过滤条件下没有匹配代码。";
        return;
    }

    for (const result of response.results) {
        const card = document.querySelector("#resultTemplate").content.cloneNode(true);
        card.querySelector(".rank").textContent = `#${result.rank}`;
        card.querySelector(".symbol-name").textContent = result.symbol_name || "未命名代码块";
        card.querySelector(".score").textContent = `RRF ${formatScore(result.final_score)}`;
        card.querySelector(".file-location").textContent = `${result.relative_path}:${result.start_line}-${result.end_line}`;
        card.querySelector(".code-content").textContent = result.content;
        card.querySelector(".keyword-score").textContent = `BM25 ${formatScore(result.keyword_score)}`;
        card.querySelector(".vector-score").textContent = `向量 ${formatScore(result.vector_score)}`;
        card.querySelector(".chunk-type").textContent = `${result.language} · ${result.chunk_type}`;
        resultCards.appendChild(card);
    }
}

function clearSearchResults(message) {
    resultCards.replaceChildren();
    rawJson.textContent = "";
    resultSummary.textContent = message;
}

function changeResultView(event) {
    const selectedView = event.currentTarget.dataset.view;
    for (const button of document.querySelectorAll(".view-button")) {
        button.classList.toggle("active", button === event.currentTarget);
    }
    resultCards.classList.toggle("hidden", selectedView !== "cards");
    rawJson.classList.toggle("hidden", selectedView !== "json");
}

function setWorkingState(button, statusBox, isWorking, message) {
    button.disabled = isWorking;
    button.textContent = isWorking ? "请求处理中……" : button.textContent;
    statusBox.className = "status-box loading";
    statusBox.textContent = message;
}

function showError(statusBox, error) {
    statusBox.className = "status-box error";
    statusBox.textContent = error.message;
}

function valueOf(id) {
    return document.querySelector(`#${id}`).value.trim();
}

function optionalValueOf(id) {
    return valueOf(id) || null;
}

function formatScore(score) {
    return score === null || score === undefined ? "无" : Number(score).toFixed(4);
}

function showSelectedFiles() {
    const selectedFiles = document.querySelector("#repositoryFiles").files;
    const totalBytes = Array.from(selectedFiles).reduce(
        (total, file) => total + file.size,
        0,
    );
    document.querySelector("#selectedFilesText").textContent =
        `已选择 ${selectedFiles.length} 个文件，共 ${formatBytes(totalBytes)}。`;
}

function removeSelectedRoot(relativePath) {
    const pathParts = relativePath.replaceAll("\\", "/").split("/");
    return pathParts.length > 1 ? pathParts.slice(1).join("/") : pathParts[0];
}

function formatBytes(byteCount) {
    if (byteCount < 1024) {
        return `${byteCount} B`;
    }
    if (byteCount < 1024 * 1024) {
        return `${(byteCount / 1024).toFixed(1)} KB`;
    }
    return `${(byteCount / 1024 / 1024).toFixed(1)} MB`;
}

checkHealth();
