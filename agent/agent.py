"""Агент ноды: единственное, что ставится на VPN-сервер.

Задачи агента:
  * принимать конфиг Xray от панели и применять его;
  * держать Xray живым (запускает его как дочерний процесс — systemd для
    самого Xray не нужен, агент и есть супервизор);
  * отдавать панели статистику трафика по пользователям и метрики сервера.

Зависимости: fastapi + uvicorn. Xray-ядро ставится отдельно (см.
scripts/install_agent.sh).

Запуск:
    AGENT_TOKEN=... python3 agent.py

Авторизация — общий bearer-токен, который панель хранит в поле node.agent_token.
Порт агента НЕ должен торчать в интернет: закройте его файрволом на все
адреса, кроме адреса панели.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import subprocess
import threading
import urllib.request
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Optional

import uvicorn
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query

# Версия агента. Увеличивается при каждом изменении этого файла: панель
# сравнивает её со своей и показывает, на каких нодах агент устарел.
AGENT_VERSION = 4

AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")
AGENT_HOST = os.getenv("AGENT_HOST", "0.0.0.0")
AGENT_PORT = int(os.getenv("AGENT_PORT", "8443"))
XRAY_BIN = os.getenv("XRAY_BIN", "/usr/local/bin/xray")
XRAY_CONFIG = Path(os.getenv("XRAY_CONFIG", "/usr/local/etc/xray/config.json"))
XRAY_ASSETS = os.getenv("XRAY_ASSETS", "/usr/local/share/xray")
XRAY_API = os.getenv("XRAY_API", "127.0.0.1:10085")
ACCESS_LOG = Path(os.getenv("XRAY_ACCESS_LOG", "/usr/local/etc/xray/access.log"))
# Сколько байт с конца access-лога читать при подсчёте устройств.
ACCESS_TAIL_BYTES = int(os.getenv("XRAY_ACCESS_TAIL", str(2 * 1024 * 1024)))
# Куда складывать вывод ядра, чтобы при падении было что показать панели.
STDOUT_LOG = Path(os.getenv("XRAY_STDOUT_LOG", "/usr/local/etc/xray/xray-stdout.log"))
# Hysteria2 — отдельный процесс рядом с Xray: QUIC, свой конфиг, свои
# счётчики. Его может не быть на ноде вовсе — тогда агент просто не станет
# его запускать, а панель увидит это в ошибке при заливке конфига.
HYSTERIA_BIN = os.getenv("HYSTERIA_BIN", "/usr/local/bin/hysteria")
HYSTERIA_CONFIG = Path(
    os.getenv("HYSTERIA_CONFIG", "/usr/local/etc/xray/hysteria.json")
)
HYSTERIA_STDOUT_LOG = Path(
    os.getenv("HYSTERIA_STDOUT_LOG", "/usr/local/etc/xray/hysteria-stdout.log")
)
HYSTERIA_CERT = Path(os.getenv("HYSTERIA_CERT", "/usr/local/etc/xray/hysteria.crt"))
HYSTERIA_KEY = Path(os.getenv("HYSTERIA_KEY", "/usr/local/etc/xray/hysteria.key"))

SSL_CERTFILE = os.getenv("SSL_CERTFILE", "")
SSL_KEYFILE = os.getenv("SSL_KEYFILE", "")

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    xray.start()
    # Конфиг Hysteria2 мог остаться с прошлого запуска — поднимаем и её,
    # иначе после перезагрузки сервера протокол молча пропал бы.
    hysteria.start()
    try:
        yield
    finally:
        hysteria.stop()
        xray.stop()


app = FastAPI(
    title="VPN Panel Node Agent", docs_url=None, redoc_url=None, lifespan=lifespan
)


def require_token(authorization: str = Header(default="")) -> None:
    if not AGENT_TOKEN:
        raise HTTPException(500, "AGENT_TOKEN не задан на ноде")
    # Сравнение в постоянном времени, чтобы токен нельзя было подобрать по таймингу.
    if not hmac.compare_digest(authorization, f"Bearer {AGENT_TOKEN}"):
        raise HTTPException(401, "Неверный токен")


def _meaningful_output(text: str, limit: int = 1200) -> str:
    """Выжимка из вывода ядра: только то, что объясняет отказ.

    Приветствие с версией и строки [Info] о чтении конфига ничего не говорят,
    а вытесняют собой саму причину.
    """
    noise = ("Penetrates Everything", "A unified platform", "[Info]", "[Debug]")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    meaningful = [
        line
        for line in lines
        if not line.startswith("Xray ") and not any(bit in line for bit in noise)
    ]
    return " ".join(meaningful or lines)[-limit:]


class XrayProcess:
    """Супервизор дочернего процесса Xray."""

    def __init__(self) -> None:
        self.process: Optional[subprocess.Popen] = None
        self.started_at: Optional[float] = None
        self.last_error: str = ""
        self.config_hash: str = ""
        # Путь берётся из применённого конфига: панель решает, куда Xray
        # пишет access-лог, и агент должен читать именно этот файл.
        self.access_log: Path = ACCESS_LOG
        self._log_handle = None

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def version(self) -> str:
        try:
            output = subprocess.run(
                [XRAY_BIN, "version"], capture_output=True, text=True, timeout=10
            ).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            self.last_error = str(exc)
            return ""
        match = re.search(r"Xray\s+([0-9][^\s(]*)", output)
        return match.group(1) if match else output.strip().splitlines()[0][:32]

    def start(self) -> None:
        if self.running:
            return
        if not XRAY_CONFIG.exists():
            self.last_error = f"нет конфига {XRAY_CONFIG}"
            return

        env = dict(os.environ, XRAY_LOCATION_ASSET=XRAY_ASSETS)
        # Вывод ядра пишем в файл, а не в трубу: причину падения Xray печатает
        # в stdout, и раньше она пропадала в DEVNULL, оставляя бесполезное
        # «xray упал». Труба тут не годится — при работе ядро пишет много,
        # буфер заполнится и процесс встанет.
        try:
            STDOUT_LOG.parent.mkdir(parents=True, exist_ok=True)
            self._log_handle = open(STDOUT_LOG, "wb")
        except OSError:
            self._log_handle = None

        try:
            self.process = subprocess.Popen(
                [XRAY_BIN, "run", "-config", str(XRAY_CONFIG)],
                env=env,
                stdout=self._log_handle or subprocess.DEVNULL,
                stderr=subprocess.STDOUT if self._log_handle else subprocess.DEVNULL,
            )
        except OSError as exc:
            self.last_error = f"не удалось запустить xray: {exc}"
            self.process = None
            return

        self.started_at = time.time()
        # Даём ядру мгновение упасть на битом конфиге, чтобы вернуть панели
        # осмысленную ошибку, а не «всё хорошо».
        time.sleep(1.0)
        if not self.running:
            self.last_error = self.output_tail() or (
                "Xray завершился сразу после запуска и ничего не написал; "
                f"его вывод на ноде — {STDOUT_LOG}"
            )
        else:
            self.last_error = ""

    def output_tail(self, limit: int = 1200) -> str:
        """Последние строки вывода ядра — то, что оно сказало перед падением."""
        if not STDOUT_LOG.exists():
            return ""
        try:
            text = STDOUT_LOG.read_text("utf-8", errors="replace")
        except OSError:
            return ""
        return _meaningful_output(text, limit)

    def test_config(self, path: Path) -> str:
        """Проверить конфиг ядром, ничего не запуская.

        `xray run -test` печатает точную причину отказа и выходит. Ошибку в
        конфиге так видно до подмены рабочего файла — Xray даже не
        перезапускается, и клиенты ничего не замечают. Порты при этом не
        занимаются, так что «адрес уже используется» ловится только на
        настоящем старте — для этого проверка и не единственная.
        """
        try:
            result = subprocess.run(
                [XRAY_BIN, "run", "-test", "-config", str(path)],
                capture_output=True,
                text=True,
                timeout=20,
                env=dict(os.environ, XRAY_LOCATION_ASSET=XRAY_ASSETS),
            )
        except (OSError, subprocess.SubprocessError):
            # Не смогли даже спросить ядро — это не повод отвергать конфиг,
            # пусть решает настоящий запуск.
            return ""
        if result.returncode == 0:
            return ""
        return _meaningful_output(result.stdout + result.stderr) or (
            f"xray run -test завершился с кодом {result.returncode}"
        )

    def stop(self) -> None:
        if not self.process:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.process = None
        self.started_at = None
        if self._log_handle is not None:
            try:
                self._log_handle.close()
            finally:
                self._log_handle = None

    def restart(self) -> None:
        self.stop()
        self.start()


xray = XrayProcess()


class HysteriaProcess:
    """Супервизор Hysteria2. Устроен проще Xray: конфиг проверяем запуском.

    Отдельный процесс нужен потому, что Hysteria2 — не транспорт Xray, а своё
    ядро: QUIC, свой формат конфига и своя статистика по пользователям.
    """

    def __init__(self) -> None:
        self.process: Optional[subprocess.Popen] = None
        self.last_error: str = ""
        self.stats_url: str = ""
        self.stats_secret: str = ""
        self._log_handle = None

    @property
    def available(self) -> bool:
        return Path(HYSTERIA_BIN).exists()

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def version(self) -> str:
        if not self.available:
            return ""
        try:
            output = subprocess.run(
                [HYSTERIA_BIN, "version"], capture_output=True, text=True, timeout=10
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return ""
        match = re.search(r"Version:\s*(\S+)", output)
        return match.group(1) if match else ""

    def output_tail(self, limit: int = 1200) -> str:
        if not HYSTERIA_STDOUT_LOG.exists():
            return ""
        try:
            return _meaningful_output(
                HYSTERIA_STDOUT_LOG.read_text("utf-8", errors="replace"), limit
            )
        except OSError:
            return ""

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process = None
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None

    def start(self) -> None:
        if self.running or not HYSTERIA_CONFIG.exists():
            return
        if not self.available:
            self.last_error = (
                f"нет бинарника {HYSTERIA_BIN} — обновите агента командой "
                "установки из панели, она его доставит"
            )
            return
        try:
            HYSTERIA_STDOUT_LOG.parent.mkdir(parents=True, exist_ok=True)
            self._log_handle = open(HYSTERIA_STDOUT_LOG, "wb")
        except OSError:
            self._log_handle = None
        try:
            self.process = subprocess.Popen(
                [HYSTERIA_BIN, "server", "-c", str(HYSTERIA_CONFIG)],
                stdout=self._log_handle or subprocess.DEVNULL,
                stderr=subprocess.STDOUT if self._log_handle else subprocess.DEVNULL,
            )
        except OSError as exc:
            self.last_error = f"не удалось запустить hysteria: {exc}"
            self.process = None
            return

        # Даём процессу мгновение упасть на битом конфиге: панели нужна
        # причина, а не «всё хорошо» с мёртвым сервером.
        time.sleep(1.5)
        self.last_error = "" if self.running else (
            self.output_tail() or "hysteria завершился сразу после запуска"
        )

    def restart(self) -> None:
        self.stop()
        self.start()

    def ensure_certificate(self, common_name: str) -> str:
        """Самоподписанный сертификат для QUIC.

        Своего домена у ноды обычно нет, а без сертификата Hysteria2 не
        поднимется вовсе. Клиент такой сертификат принимает по insecure —
        ссылку с этим флагом панель выдаёт сама.
        """
        if HYSTERIA_CERT.exists() and HYSTERIA_KEY.exists():
            return ""
        HYSTERIA_CERT.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
                    "-days", "3650", "-nodes",
                    "-keyout", str(HYSTERIA_KEY), "-out", str(HYSTERIA_CERT),
                    "-subj", f"/CN={common_name}",
                ],
                capture_output=True, text=True, timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return f"не выпустить сертификат для hysteria: {exc}"
        if result.returncode != 0:
            return f"openssl не смог выпустить сертификат: {result.stderr.strip()[:200]}"
        return ""

    def traffic(self, reset: bool = True) -> Dict[str, Dict[str, int]]:
        """Счётчики по пользователям с обнулением — как у Xray.

        В ответе Hysteria2 tx — то, что пользователь отправил, rx — что
        получил (проверено замером: скачивание даёт больший rx).
        """
        if not (self.running and self.stats_url):
            return {}
        try:
            request = urllib.request.Request(
                f"{self.stats_url}/traffic" + ("?clear=1" if reset else ""),
                headers={"Authorization": self.stats_secret},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8") or "{}")
        except Exception:
            # Статистика — не повод ронять весь ответ агента: Xray-счётчики
            # панель всё равно получит.
            return {}
        return {
            name: {
                "uplink": int(item.get("tx", 0) or 0),
                "downlink": int(item.get("rx", 0) or 0),
            }
            for name, item in data.items()
            if isinstance(item, dict)
        }


hysteria = HysteriaProcess()


def apply_hysteria(config: Optional[Dict[str, Any]]) -> None:
    """Записать конфиг Hysteria2 и перезапустить его.

    None значит «на этой ноде его быть не должно» — тогда процесс глушим,
    иначе выключённое в панели подключение продолжало бы работать.
    """
    if not config:
        hysteria.stop()
        HYSTERIA_CONFIG.unlink(missing_ok=True)
        hysteria.stats_url = ""
        return

    config = dict(config)
    common_name = config.pop("selfSignedFor", "")
    if common_name:
        problem = hysteria.ensure_certificate(str(common_name))
        if problem:
            raise HTTPException(400, problem)
        config["tls"] = {"cert": str(HYSTERIA_CERT), "key": str(HYSTERIA_KEY)}

    stats = config.get("trafficStats") or {}
    hysteria.stats_url = f"http://{stats.get('listen', '')}" if stats.get("listen") else ""
    hysteria.stats_secret = str(stats.get("secret") or "")

    HYSTERIA_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    HYSTERIA_CONFIG.write_text(
        json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    hysteria.restart()
    if not hysteria.running:
        raise HTTPException(400, f"Hysteria2 не запустилась: {hysteria.last_error}")


def _read_cpu_times() -> tuple[int, int]:
    with open("/proc/stat", "r", encoding="utf-8") as handle:
        parts = [int(value) for value in handle.readline().split()[1:]]
    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
    return sum(parts), idle


_cpu_snapshot = _read_cpu_times()


def cpu_percent() -> float:
    """Загрузка CPU между двумя вызовами /health."""
    global _cpu_snapshot
    total, idle = _read_cpu_times()
    prev_total, prev_idle = _cpu_snapshot
    _cpu_snapshot = (total, idle)
    delta_total = total - prev_total
    if delta_total <= 0:
        return 0.0
    return round(100.0 * (1 - (idle - prev_idle) / delta_total), 1)


def mem_percent() -> float:
    values: Dict[str, int] = {}
    with open("/proc/meminfo", "r", encoding="utf-8") as handle:
        for line in handle:
            key, _, rest = line.partition(":")
            values[key] = int(rest.split()[0])
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", 0)
    if not total:
        return 0.0
    return round(100.0 * (total - available) / total, 1)


def system_uptime() -> int:
    with open("/proc/uptime", "r", encoding="utf-8") as handle:
        return int(float(handle.readline().split()[0]))


@app.get("/health", dependencies=[Depends(require_token)])
def health() -> Dict[str, Any]:
    return {
        "ok": xray.running,
        "agent_version": AGENT_VERSION,
        "xray_running": xray.running,
        "xray_version": xray.version(),
        "config_hash": xray.config_hash,
        "error": xray.last_error,
        "output": xray.output_tail(400),
        "cpu_percent": cpu_percent(),
        "mem_percent": mem_percent(),
        "uptime": system_uptime(),
        "xray_uptime": int(time.time() - xray.started_at) if xray.started_at else 0,
        # Панель по этим полям понимает, есть ли на ноде Hysteria2 и жива ли
        # она: без бинарника подключение просто не поднимется.
        "hysteria_available": hysteria.available,
        "hysteria_running": hysteria.running,
        "hysteria_version": hysteria.version(),
        "hysteria_error": hysteria.last_error,
    }


@app.post("/config", dependencies=[Depends(require_token)])
def apply_config(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Записать новый конфиг и перезапустить Xray."""
    config = payload.get("config")
    if not isinstance(config, dict):
        raise HTTPException(400, "Ожидается поле config с объектом конфига")

    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)

    # Xray отказывается стартовать, если не может открыть файл access-лога, —
    # каталог под него надо создать заранее, иначе нода ляжет на пустом месте.
    access_log = (config.get("log") or {}).get("access")
    if isinstance(access_log, str) and access_log not in ("", "none"):
        try:
            Path(access_log).parent.mkdir(parents=True, exist_ok=True)
            Path(access_log).touch(exist_ok=True)
        except OSError as exc:
            raise HTTPException(
                400, f"не создать файл access-лога {access_log}: {exc}"
            ) from exc
        xray.access_log = Path(access_log)

    text = json.dumps(config, indent=2, ensure_ascii=False)

    # Отвергнутый конфиг остаётся на диске: без него причину не воспроизвести
    # руками — рабочий файл к этому моменту уже откачен на прежний.
    # Расширение обязано остаться .json: формат Xray определяет по имени файла
    # и на «config.json.rejected» отвечает «Failed to get format» — то есть
    # забраковал бы любой, даже совершенно исправный конфиг.
    rejected = XRAY_CONFIG.with_name(f"{XRAY_CONFIG.stem}.rejected.json")
    where = f"конфиг сохранён на ноде: {rejected}"

    # Сначала проверка без запуска: ошибку в конфиге ловим до того, как
    # тронули рабочий файл, и Xray продолжает работать как ни в чём не бывало.
    rejected.write_text(text, encoding="utf-8")
    problem = xray.test_config(rejected)
    if problem:
        raise HTTPException(400, f"Конфиг не принят Xray: {problem} ({where})")

    backup = XRAY_CONFIG.with_suffix(".json.bak")
    if XRAY_CONFIG.exists():
        backup.write_text(XRAY_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")

    XRAY_CONFIG.write_text(text, encoding="utf-8")
    xray.restart()

    if not xray.running:
        # Запоминаем причину до отката: перезапуск на старом конфиге пройдёт
        # успешно и затрёт last_error, а панели нужна именно первая ошибка.
        reason = xray.last_error or "Xray не запустился"
        if backup.exists():
            # Откатываемся на прошлый рабочий конфиг, чтобы нода не легла.
            XRAY_CONFIG.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8")
            xray.restart()
        raise HTTPException(400, f"Конфиг не принят Xray: {reason} ({where})")

    # Конфиг принят — держать копию отвергнутого незачем.
    rejected.unlink(missing_ok=True)

    # Hysteria2 применяем после Xray: если её конфиг забракован, Xray уже
    # работает на новом и об этом честно скажет исключение.
    apply_hysteria(payload.get("hysteria"))

    xray.config_hash = str(payload.get("hash") or "")
    return {
        "ok": True,
        "xray_running": xray.running,
        "xray_version": xray.version(),
        "hysteria_running": hysteria.running,
        "hysteria_version": hysteria.version(),
        "config_hash": xray.config_hash,
    }


@app.post("/restart", dependencies=[Depends(require_token)])
def restart() -> Dict[str, Any]:
    xray.restart()
    return {"ok": xray.running, "error": xray.last_error}


def _exit_for_restart() -> None:
    """Выйти, чтобы systemd поднял агента с новым кодом."""
    time.sleep(1.0)  # успеть отдать ответ панели
    xray.stop()
    # os._exit, а не sys.exit: мы в отдельном потоке, обычный выход его не
    # завершит процесс. Restart=always в юните поднимет агента заново.
    os._exit(0)


@app.post("/update", dependencies=[Depends(require_token)])
def update(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Заменить собственный код на присланный панелью и перезапуститься.

    Обновлять агента руками через ssh на каждой ноде — то, из-за чего он
    месяцами остаётся старым, а панель получает бесполезные сообщения об
    ошибках. Код приходит от панели, с которой агент и так связан токеном,
    так что отдельного канала доверия здесь не появляется.
    """
    source = payload.get("source")
    if not isinstance(source, str) or not source.strip():
        raise HTTPException(400, "Ожидается поле source с кодом агента")

    # Две проверки перед подменой: это действительно агент и он хотя бы
    # компилируется. Записать сюда обрывок файла — значит потерять ноду.
    if "class XrayProcess" not in source:
        raise HTTPException(400, "Присланный код не похож на агента")
    try:
        compile(source, "agent.py", "exec")
    except SyntaxError as exc:
        raise HTTPException(400, f"Присланный код не компилируется: {exc}")

    target = Path(__file__).resolve()
    try:
        backup = target.with_suffix(".py.bak")
        backup.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
        target.write_text(source, encoding="utf-8")
    except OSError as exc:
        raise HTTPException(500, f"не удалось записать {target}: {exc}")

    threading.Thread(target=_exit_for_restart, daemon=True).start()
    return {
        "ok": True,
        "previous_version": AGENT_VERSION,
        "version": payload.get("version"),
        "path": str(target),
        "restarting": True,
    }


def _query_stats(reset: bool) -> Dict[str, int]:
    command = [XRAY_BIN, "api", "statsquery", f"--server={XRAY_API}"]
    if reset:
        command.append("-reset")
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    if result.returncode != 0:
        raise HTTPException(503, f"Xray API недоступен: {result.stderr.strip()[:300]}")
    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(503, f"Не разобрать ответ Xray API: {exc}") from exc
    return {
        item["name"]: int(item.get("value", 0) or 0)
        for item in data.get("stat", [])
        if item.get("name")
    }


# Xray пишет строки вида:
# 2026/08/07 21:28:39.492233 from 127.0.0.1:54342 accepted tcp:example.com:443 \
#   [VLESS-REALITY >> DIRECT] email: user_1
# Адрес идёт сразу после "from", без указания протокола; у IPv6 он в скобках.
# Строки служебного api-inbound не содержат email и отсекаются сами.
_ACCESS_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})[^ ]* from "
    r"(?:tcp:|udp:)?\[?(?P<ip>[0-9a-fA-F.:]+?)\]?:\d+ .*email: (?P<email>\S+)"
)


@app.get("/online", dependencies=[Depends(require_token)])
def online(minutes: int = Query(default=5, ge=1, le=1440)) -> Dict[str, Any]:
    """Кто и с каких адресов подключался за последние `minutes` минут.

    Считается по access-логу Xray. Панель по этим данным показывает число
    устройств и следит за лимитом.
    """
    log_path = xray.access_log
    if not log_path.exists():
        return {"users": {}, "log": str(log_path), "available": False}

    # Читаем хвост файла: лог может быть большим, а нужны свежие строки.
    try:
        with open(log_path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - ACCESS_TAIL_BYTES))
            tail = handle.read().decode("utf-8", "replace")
    except OSError as exc:
        raise HTTPException(503, f"не читается access-лог: {exc}") from exc

    since = time.time() - minutes * 60
    users: Dict[str, set] = {}

    for line in tail.splitlines():
        match = _ACCESS_RE.match(line)
        if not match:
            continue
        try:
            moment = time.mktime(time.strptime(match.group("ts"), "%Y/%m/%d %H:%M:%S"))
        except ValueError:
            continue
        if moment < since:
            continue
        users.setdefault(match.group("email"), set()).add(match.group("ip"))

    return {
        "users": {email: sorted(ips) for email, ips in users.items()},
        "log": str(log_path),
        "available": True,
        "window_minutes": minutes,
    }


@app.get("/stats", dependencies=[Depends(require_token)])
def stats(reset: bool = Query(default=True)) -> Dict[str, Any]:
    """Счётчики трафика.

    reset=true (по умолчанию) обнуляет счётчики в Xray, поэтому панель
    получает дельту с прошлого опроса и просто прибавляет её.
    """
    raw = _query_stats(reset)

    users: Dict[str, Dict[str, int]] = {}
    inbounds: Dict[str, Dict[str, int]] = {}
    total_up = total_down = 0

    for name, value in raw.items():
        parts = name.split(">>>")
        if len(parts) != 4:
            continue
        kind, target, _, direction = parts
        if direction not in ("uplink", "downlink"):
            continue
        if kind == "user":
            users.setdefault(target, {"uplink": 0, "downlink": 0})[direction] += value
        elif kind == "inbound":
            inbounds.setdefault(target, {"uplink": 0, "downlink": 0})[
                direction
            ] += value
            if target != "api":
                if direction == "uplink":
                    total_up += value
                else:
                    total_down += value

    # Счётчики Hysteria2 приходят отдельно — складываем их с Xray, чтобы
    # панель видела один трафик пользователя, а не два по половинке.
    for username, counters in hysteria.traffic(reset).items():
        into = users.setdefault(username, {"uplink": 0, "downlink": 0})
        into["uplink"] += counters["uplink"]
        into["downlink"] += counters["downlink"]
        total_up += counters["uplink"]
        total_down += counters["downlink"]

    return {
        "users": users,
        "inbounds": inbounds,
        "total": {"uplink": total_up, "downlink": total_down},
    }


def main() -> None:
    if not AGENT_TOKEN:
        raise SystemExit("Переменная AGENT_TOKEN обязательна")
    ssl_kwargs = {}
    if SSL_CERTFILE and SSL_KEYFILE:
        ssl_kwargs = {"ssl_certfile": SSL_CERTFILE, "ssl_keyfile": SSL_KEYFILE}
    uvicorn.run(app, host=AGENT_HOST, port=AGENT_PORT, log_level="info", **ssl_kwargs)


if __name__ == "__main__":
    main()
