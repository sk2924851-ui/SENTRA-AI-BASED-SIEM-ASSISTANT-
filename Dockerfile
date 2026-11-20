FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV SENTRA_HOST=0.0.0.0 SENTRA_PORT=5000
EXPOSE 5000
# NOTE: state is held in memory and pushed over SSE, so run a single process (no multi-worker gunicorn).
# Put a reverse proxy with TLS + authentication in front before exposing this to a network.
CMD ["python", "app.py"]
