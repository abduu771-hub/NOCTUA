# SIEM-AI Backend API

This is the read-only FastAPI backend layer for the SIEM-AI UI.

## Requirements

Install the dependencies:

```bash
pip install fastapi uvicorn elasticsearch pydantic
```

## Running the API

Start the FastAPI application using uvicorn:

```bash
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

By default, the API will connect to Elasticsearch at `http://localhost:9200`. You can override this using the `SIEM_ES_URL` environment variable:

```bash
# Windows (PowerShell)
$env:SIEM_ES_URL="http://your-es-instance:9200"
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# Linux/macOS
SIEM_ES_URL="http://your-es-instance:9200" uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

## Testing the API

You can test the endpoints using curl:

```bash
curl http://localhost:8000/api/health
curl http://localhost:8000/api/overview
curl http://localhost:8000/api/events
curl http://localhost:8000/api/alerts
curl http://localhost:8000/api/incidents
```

API Documentation is automatically available at:
- Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
- ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)
