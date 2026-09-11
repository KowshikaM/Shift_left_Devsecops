FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# SQLite file lives here - mount a volume on this path to persist history
# across container restarts (see docker-compose.yml).
ENV DASHBOARD_DB_PATH=/data/dashboard.db
RUN mkdir -p /data

EXPOSE 5000

CMD ["python3", "app.py"]
