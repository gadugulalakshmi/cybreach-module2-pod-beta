import os
from typing import List

import grpc

from cybreach_service_pb2 import (
    HealthRequest,
    HealthResponse,
    RuleQueryRequest,
)
from cybreach_service_pb2_grpc import RuleIngestServiceStub


ALPHA_GRPC_HOST = os.getenv("ALPHA_GRPC_HOST", "127.0.0.1")
ALPHA_GRPC_PORT = int(os.getenv("ALPHA_GRPC_PORT", "50051"))


class AlphaGrpcClient:
    def __init__(self, host: str | None = None, port: int | None = None):
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
