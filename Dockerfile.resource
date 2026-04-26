FROM python:3.11-slim
WORKDIR /app
RUN pip install fastapi uvicorn pyjwt cryptography httpx --break-system-packages 2>/dev/null || \
    pip install fastapi uvicorn pyjwt cryptography httpx
COPY config.py resource_server.py ./
RUN mkdir -p logs
EXPOSE 8002
CMD ["python", "resource_server.py"]
