"""Версия агента и решение «пора обновлять»."""

from app.services import agent_source


def test_bundled_version_read_from_agent_file():
    """Версия берётся из самого agent.py — второго места для правки нет."""
    version = agent_source.bundled_version()
    assert version >= 2
    assert f"AGENT_VERSION = {version}" in agent_source.read_source()


def test_source_is_the_real_agent():
    source = agent_source.read_source()
    assert "class XrayProcess" in source
    # Проверка, которую делает сам агент перед подменой файла.
    compile(source, "agent.py", "exec")


def test_old_agents_without_version_count_as_outdated():
    # Агенты до самообновления не сообщают версию вовсе.
    assert agent_source.is_outdated(None, 2) is True
    assert agent_source.is_outdated(0, 2) is True
    assert agent_source.is_outdated(1, 2) is True


def test_current_and_newer_agents_are_not_outdated():
    assert agent_source.is_outdated(2, 2) is False
    # Панель откатили, а агент новее — обновлять его вниз не предлагаем.
    assert agent_source.is_outdated(3, 2) is False


def test_version_parsed_from_source_argument():
    assert agent_source.bundled_version("AGENT_VERSION = 17\n") == 17
    # Строки в комментариях и присваивания в других местах не считаются.
    assert agent_source.bundled_version("# AGENT_VERSION = 9\n") == 0
