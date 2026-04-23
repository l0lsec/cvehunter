FROM python:3.11-slim

ARG APP_VERSION
ARG APP_PACKAGE

RUN pip install --no-cache-dir "${APP_PACKAGE}==${APP_VERSION}"

WORKDIR /app
COPY app.py .

EXPOSE 5000
CMD ["python", "app.py"]
