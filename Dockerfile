FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY server ./server
COPY client ./client
COPY shared ./shared
RUN pip install --no-cache-dir .
ENV GCM_DATA_DIR=/data GCM_HOST=0.0.0.0 GCM_PORT=8080
VOLUME ["/data"]
EXPOSE 8080
CMD ["python", "-m", "gcmgamesync_server"]
