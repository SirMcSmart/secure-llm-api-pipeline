# VULNERABLE BASELINE image. Do not deploy.
# Build from the repository root: docker build -f vulnerable/Dockerfile -t docqa-vulnerable .
FROM python:3.8-slim-buster
WORKDIR /app
COPY vulnerable/requirements.txt .
RUN pip install -r requirements.txt
COPY . /app
ENV PYTHONPATH=/app/src:/app/vulnerable
EXPOSE 8000
CMD ["python", "vulnerable/app.py"]
