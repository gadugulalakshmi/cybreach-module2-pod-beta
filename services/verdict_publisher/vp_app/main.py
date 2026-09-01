from fastapi import FastAPI

from vp_app.models import PublishedVerdict


app = FastAPI(
    title="Verdict Publisher",
    version="0.1.0",
)


@app.post("/publish", response_model=PublishedVerdict)
async def publish_verdict(verdict: PublishedVerdict) -> PublishedVerdict:
    """
    Publish a validated verdict.

    Week 10 currently uses an in-memory/mock publisher.
    This endpoint represents the final stage of the Pod Beta pipeline.
    """
    print(
        f"PUBLISHED: action_id={verdict.action_id} "
        f"verdict={verdict.verdict} "
        f"confidence={verdict.confidence}"
    )

    return verdict


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "verdict_publisher",
    }
