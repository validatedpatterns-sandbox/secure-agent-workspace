FROM registry.access.redhat.com/ubi9/python-312:latest

USER 0
RUN curl -fsSL https://get.helm.sh/helm-v3.17.3-linux-amd64.tar.gz \
    | tar -xz -C /usr/local/bin --strip-components=1 linux-amd64/helm \
    && chmod +x /usr/local/bin/helm
USER 1001

COPY saw_codex_api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY saw_codex_api/ /app/saw_codex_api
COPY charts/ /app/charts/
WORKDIR /app

EXPOSE 8080
CMD ["uvicorn", "saw_codex_api.app:app", "--host", "0.0.0.0", "--port", "8080"]
