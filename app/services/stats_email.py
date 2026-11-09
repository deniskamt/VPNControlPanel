"""Метка пользователя в Xray: имя плюс номер подключения.

Xray считает трафик по полю email клиента. Пока там было одно имя, трафик
пользователя на сервере складывался в одну сумму по всем подключениям — и
нельзя было сказать, каким протоколом он пользуется. Теперь у каждого
подключения своя метка «имя|номер подключения»: счётчики раздельные, а
сумма по пользователю собирается в панели.

На вход по ключу метка не влияет: VLESS, VMess, Trojan и Shadowsocks узнают
пользователя по UUID или паролю, email — только подпись для статистики.
Разделитель «|» в именах пользователей не встречается: Marzban его не
разрешал, а боты выдают имена вида nexlo_<номер>.
"""

from typing import Optional, Tuple

SEPARATOR = "|"


def make(username: str, inbound_id: Optional[int]) -> str:
    return f"{username}{SEPARATOR}{inbound_id}" if inbound_id is not None else username


def parse(email: str) -> Tuple[str, Optional[int]]:
    """(имя, номер подключения). Старые метки без номера — (имя, None)."""
    name, sep, tail = email.rpartition(SEPARATOR)
    if sep and name and tail.isdigit():
        return name, int(tail)
    return email, None
