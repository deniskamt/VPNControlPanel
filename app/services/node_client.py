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
        self.port = node.agent_port
        self.token = node.agent_token
        self.verify = not node.agent_insecure
        self.timeout = timeout or settings.NODE_TIMEOUT

    def _explain(self, exc: Exception) -> str:
        """Превращает сетевую ошибку в понятную причину и совет.

        «All connection attempts failed» ничего не говорит администратору:
        причин ровно три, и лечатся они по-разному.
        """
        host = self.base_url

        if isinstance(exc, httpx.ConnectError):
            return (
                f"агент не отвечает на {host}. Обычно это значит, что он ещё не "
                "установлен или не запущен: проверьте на сервере "
                "`systemctl status vpn-agent`. Если панель и сервер — одна "
                "машина, укажите в поле «Адрес агента» 127.0.0.1"
            )
        if isinstance(exc, (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.TimeoutException)):
            return (
                f"таймаут при обращении к {host}. Обычно порт закрыт файрволом: "
                "разрешите его для адреса панели — "
                f"`ufw allow from <IP панели> to any port {self.port} proto tcp`"
            )
        message = str(exc) or exc.__class__.__name__
        if "certificate" in message.lower() or "ssl" in message.lower():
            return (
                f"ошибка TLS при обращении к {host}: {message}. Если у агента "
                "самоподписанный сертификат, включите «не проверять сертификат»"
            )
        return f"нет связи с агентом ({host}): {message}"

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
            raise NodeError(self._explain(exc)) from exc

        if response.status_code == 401:
            raise NodeError(
                "агент отверг токен. Токен в панели и AGENT_TOKEN в "
                "/opt/vpn-agent/agent.env на сервере должны совпадать; "
                "после правки — `systemctl restart vpn-agent`"
            )
        if response.status_code == 404:
            raise NodeError(
                f"на {self.base_url} отвечает не агент панели, а что-то другое — "
                "проверьте порт"
            )
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

    async def online(self, minutes: int = 5) -> Dict[str, Any]:
        """Адреса, с которых подключались пользователи — для счёта устройств."""
        return await self._request("GET", "/online", params={"minutes": minutes})

    async def stats(self, reset: bool = True) -> Dict[str, Any]:
        return await self._request("GET", "/stats", params={"reset": str(reset).lower()})

    async def restart(self) -> Dict[str, Any]:
        return await self._request("POST", "/restart", timeout=max(self.timeout, 30))
