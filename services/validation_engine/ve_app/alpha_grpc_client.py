import os
from typing import List

import grpc

# The generated stubs are a build artifact, produced by
#   python -m grpc_tools.protoc -Iproto --python_out=. --grpc_python_out=. \
#       proto/cybreach_service.proto
# and are deliberately not committed. Importing them here at module scope would
# make `ve_app.main` unimportable in any environment where codegen has not run,
# so the Alpha gRPC path is opt-in and fails only when it is actually taken --
# the same shape as `ve_app.grpc_server`, which `start_grpc_server` imports
# lazily for the same reason.
try:
    from cybreach_service_pb2 import (
        HealthRequest,
        RuleQueryRequest,
    )
    from cybreach_service_pb2_grpc import RuleIngestServiceStub

    STUBS_AVAILABLE = True
except ImportError:  # pragma: no cover - requires a codegen step
    HealthRequest = RuleQueryRequest = RuleIngestServiceStub = None
    STUBS_AVAILABLE = False


_STUB_HINT = (
    "Alpha gRPC stubs are not generated. Run: python -m grpc_tools.protoc "
    "-Iproto --python_out=. --grpc_python_out=. proto/cybreach_service.proto"
)


ALPHA_GRPC_HOST = os.getenv("ALPHA_GRPC_HOST", "127.0.0.1")
ALPHA_GRPC_PORT = int(os.getenv("ALPHA_GRPC_PORT", "50051"))


class AlphaGrpcClient:
    def __init__(self, host: str | None = None, port: int | None = None):
        if not STUBS_AVAILABLE:
            raise RuntimeError(_STUB_HINT)
        self.host = host or ALPHA_GRPC_HOST
        self.port = port or ALPHA_GRPC_PORT
        self.channel = grpc.insecure_channel(f"{self.host}:{self.port}")
        self.stub = RuleIngestServiceStub(self.channel)

    def fetch_rules(self, tenant_id: str = "default", rule_query: str = "*", limit: int = 50):
        try:
            response = self.stub.FetchRules(
                RuleQueryRequest(
                    tenant_id=tenant_id,
                    rule_query=rule_query,
                    limit=limit,
                )
            )
            return [
                {
                    "rule_id": rule.rule_id,
                    "rule_name": rule.rule_name,
                    "rule_query": rule.rule_query,
                    "source": rule.source,
                    "mitre_techniques": ["T1059"],
                }
                for rule in response.rules
            ]
        except Exception as exc:
            raise RuntimeError(f"Alpha gRPC fetch failed: {exc}") from exc

    def health(self):
        response = self.stub.HealthCheck(
            HealthRequest(service_name="beta-validation-engine")
        )
        return {
            "status": response.status,
            "service": response.service,
            "timestamp": response.timestamp,
            "version": response.version,
        }
