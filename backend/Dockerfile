FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/rung /app/rung
COPY backend/app /app/app
COPY backend/data /app/data
ENV PYTHONPATH=/app:/app/rung/src
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]