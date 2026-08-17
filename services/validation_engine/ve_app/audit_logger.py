import logging

logger = logging.getLogger("validation_engine.audit")

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

logger.setLevel(logging.INFO)


def audit_event(event: str, **details) -> None:
    """Record a structured audit event for validation processing."""

    detail_text = " ".join(
        f"{key}={value}" for key, value in details.items()
    )

    if detail_text:
        logger.info("%s | %s", event, detail_text)
    else:
        logger.info("%s", event)