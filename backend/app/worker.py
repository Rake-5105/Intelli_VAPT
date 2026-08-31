"""Celery worker entry points for background scan tasks."""

from .main import celery_app


@celery_app.task(bind=True, autoretry_for=(OSError,), retry_backoff=True, max_retries=2)
def execute_authorized_scan(self, scan_id: str):
    """Reserved worker entry point; real scanner adapters must validate scope again."""
    return {"scan_id": scan_id, "status": "queued"}
