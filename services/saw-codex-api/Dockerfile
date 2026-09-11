FROM registry.access.redhat.com/ubi9/python-312:latest

USER 0
RUN dnf install -y --setopt=install_weak_deps=False helm && dnf clean all
USER 1001

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/saw_codex_api
WORKDIR /app

EXPOSE 8080
CMD ["uvicorn", "saw_codex_api.app:app", "--host", "0.0.0.0", "--port", "8080"]
