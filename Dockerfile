FROM python:3.14-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements-test.txt .

RUN pip install --no-cache-dir -r requirements-test.txt

COPY hashcheck.py .
COPY tests/ ./tests/

RUN mkdir -p /app/tests/results

CMD ["python", "tests/run_suite.py"]
