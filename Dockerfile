FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends curl libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m pip install --upgrade pip \
    && python -m pip install torch --index-url https://download.pytorch.org/whl/cpu \
    && python -m pip install --requirement requirements.txt

# 依赖层只在 requirements.txt 改变时重建；业务代码修改不会重新下载 PyTorch。
COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config
RUN python -m pip install --no-deps .

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "secval.web_api.search_api:app", "--host", "0.0.0.0", "--port", "8000"]
