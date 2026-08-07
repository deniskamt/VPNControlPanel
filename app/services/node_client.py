"""HTTP-клиент к агенту ноды."""

from typing import Any, Dict

import httpx

from app.core.config import settings
from app.models.node import Node


class NodeError(Exception):
    """Нода недоступна или вернула ошибку."""


class NodeClient:
    def __init__(self, node: Node, timeout: int | None = None) -> None:
        self.base_url = node.agent_base_url
        self.token = node.agent_token
        self.verify = not node.agent_insecure
        self.timeout = timeout or settings.NODE_TIMEOUT

    async def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=self.verify
            ) as client:
                response = await client.request(
                    method, f"{self.base_url}{path}", headers=headers, **kwargs
                )
        except httpx.HTTPError as exc:
            raise NodeError(f"нет связи с агентом: {exc}") from exc

        if response.status_code >= 400:
            detail = response.text[:300]
            try:
                detail = response.json().get("detail", detail)
            except ValueError:
                pass
            raise NodeError(f"агент вернул {response.status_code}: {detail}")

        try:
            return response.json()
        except ValueError as exc:
            raise NodeError("агент вернул не JSON") from exc

    async def health(self) -> Dict[str, Any]:
        return await self._request("GET", "/health")

    async def apply_config(self, config: Dict[str, Any], config_hash: str) -> Dict[str, Any]:
        # Заливка конфига перезапускает Xray, это заметно дольше health-check.
        return await self._request(
            "POST",
            "/config",
            json={"config": config, "hash": config_hash},
            timeout=max(self.timeout, 30),
        )

    async def stats(self, reset: bool = True) -> Dict[str, Any]:
        return await self._request("GET", "/stats", params={"reset": str(reset).lower()})

    async def restart(self) -> Dict[str, Any]:
        return await self._request("POST", "/restart", timeout=max(self.timeout, 30))
