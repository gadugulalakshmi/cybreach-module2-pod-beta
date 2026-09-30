import time
from concurrent import futures

import grpc

from cybreach_service_pb2 import (
    BatchValidateRequest,
    BatchValidateResponse,
    ClassifyRequest,
    ClassifyResponse,
    HealthResponse,
    ValidateRequest,
    ValidateResponse,
)
from cybreach_service_pb2_grpc import (
    ClassificationServiceServicer,
    ValidationServiceServicer,
    add_ClassificationServiceServicer_to_server,
    add_ValidationServiceServicer_to_server,
)

from ve_app.main import build_verdict, validate_evidence
from ve_app.models import EvidenceEvent


class BetaValidationServiceServicer(ValidationServiceServicer):
    def Validate(self, request, context):
        try:
            evidence = EvidenceEvent.model_validate_json(
                request.normalized_event.decode("utf-8")
            )
            rules = []
            if request.rule_ids:
                rules = [
                    {"rule_id": rid, "technique_ref": "T1059", "keywords": []}
                    for rid in request.rule_ids
                ]
            verdict = validate_evidence(evidence, rules)
            return ValidateResponse(
                verdict_id=getattr(verdict, "action_id", "unknown"),
                status="valid",
                matched_rules=[verdict.rule_id] if verdict.rule_id else [],
                error_detail="",
            )
        except Exception as exc:
            context.abort(grpc.StatusCode.INTERNAL, str(exc))

    def BatchValidate(self, request, context):
        responses = [self.Validate(item, context) for item in request.requests]
        return BatchValidateResponse(
            responses=responses,
            success_count=len(responses),
            failed_count=0,
        )

    def HealthCheck(self, request, context):
        return HealthResponse(
            status="ok",
            service="beta-validation-engine",
            timestamp=int(time.time()),
            version="1.0",
        )


class BetaClassificationServiceServicer(ClassificationServiceServicer):
    def Classify(self, request, context):
        return ClassifyResponse(
            verdict_id=request.verdict_id,
            risk_level="medium",
            causal_chain=["grpc_classify_received"],
            classification_detail="gRPC classification path active",
        )

    def HealthCheck(self, request, context):
        return HealthResponse(
            status="ok",
            service="beta-outcome-classifier",
            timestamp=int(time.time()),
            version="1.0",
        )


def serve(host: str = "0.0.0.0", port: int = 50052):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_ValidationServiceServicer_to_server(BetaValidationServiceServicer(), server)
    add_ClassificationServiceServicer_to_server(
        BetaClassificationServiceServicer(), server
    )
    server.add_insecure_port(f"{host}:{port}")
    server.start()
    print(f"[Beta gRPC] ValidationService + ClassificationService listening on {host}:{port}")
    server.wait_for_termination()
