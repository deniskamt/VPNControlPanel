"""Маскировочные домены REALITY: каталог, выбор и свой домен у каждого сервера.

Почему каталог, а не пять доменов. Домены из популярных гайдов —
www.microsoft.com, dl.google.com, www.samsung.com — стоят в каждом втором
конфиге. Сочетание «SNI крупного сайта, а IP — дешёвый VPS» по ним
вычисляется статистикой, и, судя по сообщениям 2025–2026 годов, так РКН
и работает. www.cloudflare.com в России вдобавок режется сам по себе. Поэтому
на практике выживает малоизвестный домен, а одинаковый домен на всех
серверах — одна примета на весь сервис.

Каталог — это кандидаты, а не проверенный список. Годится ли домен,
решает сама нода: TLS 1.3, HTTP/2, сертификат и задержка зависят от того,
откуда смотреть. Проверку с нод делает агент (POST /probe), а панель
показывает её в разделе «Подключения» → «Подбор маскировки».
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence


@dataclass(frozen=True)
class Group:
    title: str
    note: str
    domains: Sequence[str]
    recommended: bool = True
    # Страны нод, которым эта группа ближе всего (коды ISO, как у серверов).
    countries: Sequence[str] = ()


CATALOG: List[Group] = [
    # Нишевые сайты: магазины электроники и музыки, профильные издания,
    # локальные сервисы. В гайдах их нет, у корпораций с мировым CDN они не
    # живут, а трафик к ним из любой страны выглядит обычным. Годится ли
    # домен, всё равно решает проверка с самого сервера (TLS 1.3, HTTP/2,
    # сертификат, задержка) — каталог только даёт кандидатов.
    Group(
        "Япония — нишевые",
        "Студии, издательства и магазины аниме и хобби: в гайдах их нет. "
        "Отсюда и www.lovelive-anime.jp, который у вас работал.",
        [
            "www.lovelive-anime.jp",
            "www.aniplex.co.jp",
            "www.sunrise-inc.co.jp",
            "www.goodsmile.info",
            "www.animate.co.jp",
            "www.toranoana.jp",
            "www.melonbooks.co.jp",
            "www.mandarake.co.jp",
            "www.kotobukiya.co.jp",
            "www.amiami.com",
        ],
        countries=("JP", "KR", "TW", "HK", "SG", "MY"),
    ),
    Group(
        "Финляндия и Скандинавия — нишевые",
        "Местные магазины и сервисы: рядом с финскими и шведскими "
        "дата-центрами, за пределами региона почти неизвестны.",
        [
            "www.motonet.fi",
            "www.tokmanni.fi",
            "www.suomalainen.com",
            "www.jimms.fi",
            "www.proshop.fi",
            "www.webhallen.com",
            "www.inet.se",
            "www.jula.se",
            "www.biltema.se",
            "www.komplett.no",
            "www.proshop.dk",
        ],
        countries=("FI", "SE", "NO", "DK", "EE", "LV", "LT", "IS"),
    ),
    Group(
        "Германия и Центральная Европа — нишевые",
        "Магазины техники и музыки, профильные издания — для нод в "
        "Германии, Польше, Чехии, Австрии, Швейцарии.",
        [
            "www.thomann.de",
            "www.reichelt.de",
            "www.mindfactory.de",
            "www.alternate.de",
            "www.caseking.de",
            "www.computerbase.de",
            "www.golem.de",
            "www.x-kom.pl",
            "www.morele.net",
            "www.czc.cz",
            "www.digitec.ch",
        ],
        countries=("DE", "PL", "CZ", "AT", "CH", "SK", "HU"),
    ),
    Group(
        "Нидерланды, Бельгия, Франция, Великобритания — нишевые",
        "Местные магазины электроники и профильные сайты — для нод в "
        "Амстердаме, Париже, Лондоне и рядом.",
        [
            "www.tweakers.net",
            "www.megekko.nl",
            "www.azerty.nl",
            "www.alternate.nl",
            "www.ldlc.com",
            "www.materiel.net",
            "www.topachat.com",
            "www.scan.co.uk",
            "www.overclockers.co.uk",
            "www.ebuyer.com",
        ],
        countries=("NL", "BE", "FR", "LU", "GB", "IE", "ES", "PT", "IT"),
    ),
    Group(
        "Известные компании — не рекомендуются",
        "Крупные бренды: сочетание «SNI корпорации, а IP — дешёвый VPS» "
        "вычисляется статистикой. Оставлены, чтобы старые подключения было "
        "видно в списке; сами не подбираются.",
        [
            "www.square-enix.com", "www.capcom.co.jp", "www.konami.com", "www.sega.co.jp",
            "www.kadokawa.co.jp", "www.bandainamco.co.jp", "www.toho.co.jp", "www.sanrio.co.jp",
            "www.yamaha.com", "www.casio.com",
            "www.kone.com", "www.wartsila.com", "www.fiskars.com", "www.nokia.com",
            "www.ericsson.com", "www.electrolux.com", "www.husqvarna.com", "www.sandvik.com",
            "www.scania.com", "www.volvocars.com", "www.abb.com",
            "www.miele.com", "www.zeiss.com", "www.basf.com", "www.continental.com",
            "www.henkel.com", "www.siemens.com", "www.bosch.com", "www.sap.com",
            "www.otto.de", "www.mediamarkt.de",
            "www.asml.com", "www.heineken.com", "www.ing.com", "www.philips.com",
            "www.schneider-electric.com", "www.decathlon.com", "www.leroymerlin.fr",
            "www.lg.com", "www.panasonic.com", "www.canon.com", "www.nikon.com",
            "www.logitech.com", "www.asus.com", "www.acer.com", "www.lenovo.com",
            "www.tp-link.com", "www.autodesk.com", "www.ubisoft.com", "www.gog.com",
        ],
        recommended=False,
    ),
    Group(
        "Популярные — из гайдов, не рекомендуются",
        "Стоят в каждом втором конфиге и вычисляются в первую очередь. "
        "www.cloudflare.com в России режется сам по себе.",
        [
            "www.microsoft.com",
            "www.samsung.com",
            "www.cloudflare.com",
            "dl.google.com",
        ],
        recommended=False,
    ),
]

ALL_DOMAINS: List[str] = [domain for group in CATALOG for domain in group.domains]
RECOMMENDED: List[str] = [
    domain for group in CATALOG if group.recommended for domain in group.domains
]
DISCOURAGED: frozenset = frozenset(
    domain for group in CATALOG if not group.recommended for domain in group.domains
)

# Имя хоста: метки из букв, цифр и дефисов через точку, без схемы и порта.
_DOMAIN = re.compile(
    r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

# Ключ в настройках подключения: свой домен для каждого сервера.
NODE_DOMAINS_KEY = "nodeDomains"


def clean(value: Optional[str]) -> str:
    """Привести ввод к имени хоста: без схемы, пути, порта и пробелов.

    Люди вставляют сюда «https://www.example.com/» или «example.com:443» —
    это то же самое имя, и отказывать из-за обёртки незачем.
    """
    text = (value or "").strip().lower()
    text = re.sub(r"^[a-z]+://", "", text)
    text = text.split("/", 1)[0]
    text = text.rsplit(":", 1)[0] if re.search(r":\d+$", text) else text
    return text.rstrip(".")


def is_valid(domain: str) -> bool:
    return bool(_DOMAIN.match(domain))


def pick_default(taken: Iterable[str] = ()) -> str:
    """Домен для нового подключения, если его не выбрали.

    Не первый из списка, а случайный рекомендованный и ещё не занятый: при
    фиксированном значении по умолчанию все подключения получали бы один
    и тот же домен — ту самую одну примету на весь сервис.
    """
    used = set(taken)
    free = [domain for domain in RECOMMENDED if domain not in used]
    return random.choice(free or RECOMMENDED)


def node_domains(settings: Optional[Dict]) -> Dict[str, str]:
    """Свои домены серверов: {номер сервера: домен}."""
    raw = (settings or {}).get(NODE_DOMAINS_KEY) or {}
    return {str(key): value for key, value in raw.items() if value}


def domain_for(settings: Optional[Dict], node_id: Optional[int]) -> Optional[str]:
    """Домен, под который подключение маскируется на этом сервере.

    Свой домен сервера, если задан; иначе общий из настроек подключения.
    """
    own = node_domains(settings).get(str(node_id)) if node_id is not None else None
    if own:
        return own
    names = (settings or {}).get("serverNames") or []
    return names[0] if names else None


def duplicates(settings: Optional[Dict], node_ids: Iterable[int]) -> Dict[str, List[int]]:
    """Домены, которые достались сразу нескольким серверам одного подключения.

    Одинаковый домен — одна примета на все серверы. А за передним сервером
    это ещё и техническая ошибка: nginx различает ноды только по имени.
    """
    seen: Dict[str, List[int]] = {}
    for node_id in node_ids:
        domain = domain_for(settings, node_id)
        if domain:
            seen.setdefault(domain, []).append(node_id)
    return {domain: ids for domain, ids in seen.items() if len(ids) > 1}


# --- Результаты проверки с нод ------------------------------------------------

def summarize(results_by_node: Dict[int, List[Dict]]) -> List[Dict]:
    """Свести ответы нод в таблицу «домен × сервер».

    Выше — домены, которые годятся на большем числе серверов, при равенстве —
    с меньшей задержкой. Популярные домены из гайдов опускаются вниз, даже
    если технически годятся: проблема у них не в TLS.
    """
    rows: Dict[str, Dict] = {}
    for node_id, results in results_by_node.items():
        for item in results:
            row = rows.setdefault(
                item["domain"],
                {"domain": item["domain"], "by_node": {}, "ok_count": 0, "ms": []},
            )
            row["by_node"][node_id] = item
            if item.get("ok"):
                row["ok_count"] += 1
                if item.get("ms") is not None:
                    row["ms"].append(item["ms"])

    for row in rows.values():
        row["best_ms"] = min(row["ms"]) if row["ms"] else None
        row["discouraged"] = row["domain"] in DISCOURAGED

    return sorted(
        rows.values(),
        key=lambda row: (
            row["discouraged"],
            -row["ok_count"],
            row["best_ms"] if row["best_ms"] is not None else 10**9,
            row["domain"],
        ),
    )


def assign_distinct(
    node_ids: Sequence[int], results_by_node: Dict[int, List[Dict]]
) -> Dict[int, str]:
    """Каждому серверу — свой годный домен с наименьшей задержкой от него.

    Домены не повторяются между серверами, популярные из гайдов не берутся.
    Сервер, для которого годного свободного домена не нашлось, в ответ не
    попадает — у него останется общий домен подключения.
    """
    taken: set = set()
    chosen: Dict[int, str] = {}
    # Сначала те, у кого выбор меньше: иначе сервер с одним годным доменом
    # может остаться ни с чем, потому что его домен забрал сосед.
    def candidates(node_id: int) -> List[Dict]:
        return sorted(
            (
                item
                for item in results_by_node.get(node_id, [])
                if item.get("ok") and item["domain"] not in DISCOURAGED
                and not is_russian(item["domain"])
            ),
            key=lambda item: (item.get("ms") or 10**9, item["domain"]),
        )

    for node_id in sorted(node_ids, key=lambda nid: len(candidates(nid))):
        for item in candidates(node_id):
            if item["domain"] not in taken:
                chosen[node_id] = item["domain"]
                taken.add(item["domain"])
                break
    return chosen


def assign_from_catalog(
    nodes: Sequence, taken: Iterable[str] = (), current: Optional[Dict] = None
) -> Dict[int, str]:
    """Каждому серверу — свой домен из каталога, без проверки с нод.

    Сначала из группы, близкой к стране сервера (финской ноде — северные
    компании, немецкой — немецкие), потом из остальных рекомендованных.
    Домены не повторяются ни между серверами, ни с уже занятыми — например,
    другими подключениями. Серверу, у которого свой домен уже есть и он ни с
    кем не совпадает, его оставляем: менять работающее незачем.
    """
    used = set(taken)
    chosen: Dict[int, str] = {}
    own = node_domains(current)

    # Свои непересекающиеся домены — сохраняем как есть.
    counts: Dict[str, int] = {}
    for node in nodes:
        domain = own.get(str(node.id))
        if domain:
            counts[domain] = counts.get(domain, 0) + 1
    for node in nodes:
        domain = own.get(str(node.id))
        if domain and counts[domain] == 1 and domain not in DISCOURAGED and domain not in used:
            chosen[node.id] = domain
            used.add(domain)

    for node in nodes:
        if node.id in chosen:
            continue
        country = (getattr(node, "country", "") or "").upper()
        near = [d for g in CATALOG if g.recommended and country in g.countries for d in g.domains]
        for domain in near + [d for d in RECOMMENDED if d not in near]:
            if domain not in used:
                chosen[node.id] = domain
                used.add(domain)
                break
    return chosen


# --- Соседи по подсети ------------------------------------------------------------

# Российские зоны: иностранный сервер под SNI российского сайта — странная
# пара, такую маскировку не берём. Мостам (сервер в России) — наоборот, нужны
# именно они (services/bridge.py), поэтому там отсев выключается.
RUSSIAN_ZONES = (".ru", ".su", ".xn--p1ai", ".рф")


def is_russian(domain: str) -> bool:
    name = (domain or "").lower().rstrip(".")
    return name.endswith(RUSSIAN_ZONES)


def usable_neighbors(results: Sequence[Dict], allow_russian: bool = False) -> List[Dict]:
    """Годные соседи: TLS 1.3, HTTP/2, сертификат и DNS в той же подсети,
    не популярные из гайдов и (для иностранных серверов) не .ru/.su/.рф."""
    return [
        item for item in results
        if item.get("ok") and item.get("same_subnet") and item["domain"] not in DISCOURAGED
        and (allow_russian or not is_russian(item["domain"]))
    ]


def assign_from_neighbors(
    node_ids: Sequence[int], neighbors_by_node: Dict[int, List[Dict]], taken: Iterable[str] = ()
) -> Dict[int, str]:
    """Каждому серверу — свой сосед по подсети с наименьшей задержкой."""
    used = set(taken)
    chosen: Dict[int, str] = {}
    for node_id in node_ids:
        for item in sorted(usable_neighbors(neighbors_by_node.get(node_id, [])),
                           key=lambda r: (r.get("ms") or 10**6, r["domain"])):
            if item["domain"] not in used:
                chosen[node_id] = item["domain"]
                used.add(item["domain"])
                break
    return chosen


def assign_random_neighbors(
    node_ids: Sequence[int],
    neighbors_by_node: Dict[int, List[Dict]],
    taken: Iterable[str] = (),
    current: Optional[Dict[int, str]] = None,
    rng=None,
) -> Dict[int, str]:
    """Каждому серверу — случайный годный сосед по подсети.

    Случайный, а не самый быстрый: одинаковый выбор по задержке со временем
    даёт одинаковые домены у похожих серверов, а смена «на следующий по
    списку» предсказуема. Домены не повторяются между серверами и с уже
    занятыми; нынешний домен сервера берётся, только если другого нет.
    Сервер без годных соседей в ответ не попадает.
    """
    import random

    rng = rng or random.SystemRandom()
    current = current or {}
    used = set(taken)
    chosen: Dict[int, str] = {}
    # Сначала те, у кого выбор меньше, — как в assign_distinct.
    pools = {
        node_id: [item["domain"] for item in usable_neighbors(neighbors_by_node.get(node_id, []))]
        for node_id in node_ids
    }
    for node_id in sorted(node_ids, key=lambda nid: (len(pools[nid]), nid)):
        free = [domain for domain in pools[node_id] if domain not in used]
        fresh = [domain for domain in free if domain != current.get(node_id)]
        pick_from = fresh or free
        if not pick_from:
            continue
        domain = rng.choice(pick_from)
        chosen[node_id] = domain
        used.add(domain)
    return chosen


# --- Лучший домен для сервера ----------------------------------------------------

def _same_24(ip_a: str, ip_b: str) -> bool:
    return bool(ip_a and ip_b) and ip_a.rsplit(".", 1)[0] == ip_b.rsplit(".", 1)[0]


def rank_for_node(
    node_ip: str,
    country: Optional[str],
    neighbors: Sequence[Dict],
    probed: Sequence[Dict],
    taken: Iterable[str] = (),
) -> List[Dict]:
    """Кандидаты в маскировку сервера — от лучшего к худшему.

    1. Соседи по подсети (годные): сначала из той же /24, что и сервер, —
       ближе всего к «обычному» трафику, — потом остальные; внутри — по
       задержке.
    2. Нишевые домены из каталога, годные по проверке с этого сервера:
       сначала из группы его страны, потом остальные; внутри — по задержке.
    Без занятых другими серверами, популярных, известных компаний и
    российских зон.
    """
    used = set(taken)
    near_country = {
        domain for group in CATALOG if group.recommended
        and (country or "").upper() in group.countries for domain in group.domains
    }
    ranked: List[Dict] = []
    for item in sorted(
        (i for i in usable_neighbors(neighbors) if i["domain"] not in used),
        key=lambda i: (not _same_24(node_ip, i.get("neighbor_ip") or ""),
                       i.get("ms") or 10**6, i["domain"]),
    ):
        ranked.append({"domain": item["domain"], "source": "сосед", "ms": item.get("ms")})
    recommended = set(RECOMMENDED)
    for item in sorted(
        (i for i in probed if i.get("ok") and i["domain"] in recommended
         and i["domain"] not in used and not is_russian(i["domain"])),
        key=lambda i: (i["domain"] not in near_country, i.get("ms") or 10**6, i["domain"]),
    ):
        if all(r["domain"] != item["domain"] for r in ranked):
            ranked.append({"domain": item["domain"], "source": "каталог", "ms": item.get("ms")})
    return ranked


def assign_best(
    ranked_by_node: Dict[int, List[Dict]], blocked: Iterable[str] = ()
) -> Dict[int, Dict]:
    """Каждому серверу — лучший свободный кандидат, без повторов.
    blocked — домены, которые не открываются из России (проверка зондом)."""
    bad = set(blocked)
    used: set = set()
    chosen: Dict[int, Dict] = {}
    for node_id in sorted(ranked_by_node, key=lambda nid: (len(ranked_by_node[nid]), nid)):
        for item in ranked_by_node[node_id]:
            if item["domain"] not in used and item["domain"] not in bad:
                chosen[node_id] = item
                used.add(item["domain"])
                break
    return chosen
