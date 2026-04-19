"""
vulnalyzer.api
==============
Reserved for FastAPI route handlers.

Suggested structure when adding the API layer:

    vulnalyzer/api/
    ├── __init__.py       ← this file
    ├── app.py            ← FastAPI app factory
    ├── routes/
    │   ├── vulns.py      ← GET /vulns, GET /vulns/{id}
    │   ├── repos.py      ← POST /scan, GET /repos
    │   ├── graph.py      ← GET /graph, GET /graph?ecosystem=npm
    │   └── metrics.py    ← GET /metrics/blast-radius/{cve}
    └── schemas.py        ← Pydantic models

Example app.py skeleton:

    from fastapi import FastAPI
    from vulnalyzer.api.routes import vulns, repos, graph, metrics

    def create_app() -> FastAPI:
        app = FastAPI(title="Vulnalyzer API", version="0.1.0")
        app.include_router(vulns.router,   prefix="/vulns")
        app.include_router(repos.router,   prefix="/repos")
        app.include_router(graph.router,   prefix="/graph")
        app.include_router(metrics.router, prefix="/metrics")
        return app

To run:
    uvicorn vulnalyzer.api.app:create_app --factory --reload
"""
