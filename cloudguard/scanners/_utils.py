"""Shared read-only scanner helpers."""

from typing import Any, Dict, List, Optional


def collect_pages(
    client: Any,
    operation_name: str,
    result_key: str,
    params: Optional[Dict[str, Any]] = None,
    token_param: str = "NextToken",
    token_field: str = "NextToken",
    truncated_field: Optional[str] = None,
) -> List[Any]:
    """Collect all API result pages, failing rather than silently truncating."""
    request = dict(params or {})
    results: List[Any] = []
    seen_tokens = set()

    while True:
        response = getattr(client, operation_name)(**request)
        results.extend(response.get(result_key, []))

        if truncated_field and not response.get(truncated_field, False):
            break
        token = response.get(token_field)
        if not token:
            if truncated_field and response.get(truncated_field, False):
                raise RuntimeError(f"{operation_name} returned a truncated response without a continuation token.")
            break
        if token in seen_tokens:
            raise RuntimeError(f"{operation_name} repeated a continuation token; results may be incomplete.")
        seen_tokens.add(token)
        request[token_param] = token

    return results