# Architecture

The frontend is a Vite/React client. It uses the FastAPI REST API for authentication and project data. The API persists operational records in PostgreSQL in Docker deployments and can use SQLite for local development. Redis and Celery provide the worker boundary for long-running scanner work.

Scanner integrations must receive an approved project target, validate it again at worker execution time, and use `subprocess.run` with argument arrays. Files belong under `storage/`; only metadata and SHA-256 integrity hashes belong in the database.
