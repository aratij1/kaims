"""Stable metric identities; never use request IDs or query values as labels."""
from starlette.requests import Request


def gateway_metric_operation(request: Request) -> str:
    route = request.scope.get("route")
    return getattr(route, "path", None) or "unmatched"
