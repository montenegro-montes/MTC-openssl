FROM python:3.12-slim
WORKDIR /app
COPY src/mtc/core.py src/mtc/trust_anchor_ids.py src/mtc/local_log.py src/mtc/log_service.py ./
ENV PYTHONDONTWRITEBYTECODE=1
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["python3", "-B", "/app/log_service.py", "--host", "0.0.0.0", "--data", "/data"]
CMD ["--port", "8080"]
