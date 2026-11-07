FROM python:3.11-slim
WORKDIR /app

RUN pip install --no-cache-dir "Flask>=3.0" "waitress>=3.0"

COPY common /app/common
COPY reporter /app/reporter
COPY config /app/config

RUN useradd --system --no-create-home sentinel && mkdir -p /app/logs && chown sentinel /app/logs
USER sentinel

# It reads the token that `sentinel.py token` created in the data folder.
ENV SENTINELAI_DASHBOARD_HOST=0.0.0.0
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/api/health', timeout=2)"
CMD ["python", "-m", "reporter.web_dashboard"]
