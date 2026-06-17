import json

import pytest

from loguru import logger


class JsonSink:
    def __init__(self):
        self.dict = None
        self.json = None

    def write(self, message):
        self.dict = message.record
        self.json = json.loads(message)


def test_translate_basic_message(writer):
    logger.add(writer, format="{message}")

    logger.translate(lambda message: message.replace("Hello", "Bonjour")).info("Hello world")

    assert writer.read() == "Bonjour world\n"


def test_translate_receives_formatted_message(writer):
    seen = []

    def translator(message):
        seen.append(message)
        return message.upper()

    logger.add(writer, format="{message}")

    logger.translate(translator).info("Hello {}", "world")

    assert seen == ["Hello world"]
    assert writer.read() == "HELLO WORLD\n"


def test_chained_translators_are_applied_in_order(writer):
    logger.add(writer, format="{message}")

    logger.translate(lambda message: message + " beta").translate(
        lambda message: message.replace("beta", "gamma")
    ).info("alpha")

    assert writer.read() == "alpha gamma\n"


def test_translate_after_patch_uses_patched_message(writer):
    def patcher(record):
        record["message"] = "patched " + record["message"]

    logger.add(writer, format="{message}")

    logger.patch(patcher).translate(lambda message: message.upper()).info("message")

    assert writer.read() == "PATCHED MESSAGE\n"


def test_translate_combines_with_bind_and_opt_record(writer):
    logger.add(writer, format="{extra[user]} {extra[action]} {message}")

    logger.bind(user="Ada").translate(lambda message: message.upper()).opt(record=True).info(
        "{record[extra][user]} {action}", action="login"
    )

    assert writer.read() == "Ada login ADA LOGIN\n"


def test_translate_does_not_affect_parent_logger(writer):
    logger.add(writer, format="{message}")

    translated = logger.translate(lambda message: "translated " + message)

    logger.info("parent")
    translated.info("child")

    assert writer.read() == "parent\ntranslated child\n"


def test_translate_allows_empty_string(writer):
    logger.add(writer, format="{level.name}:{message}")

    logger.translate(lambda message: "").info("hidden")

    assert writer.read() == "INFO:\n"


def test_translate_exception_is_not_caught_by_handler_catch(writer):
    def broken_translator(message):
        raise RuntimeError("translation failed")

    logger.add(writer, format="{message}", catch=True)

    with pytest.raises(RuntimeError, match="translation failed"):
        logger.translate(broken_translator).info("secret")

    assert writer.read() == ""


def test_translate_updates_serialized_text_and_record():
    sink = JsonSink()
    logger.add(sink, format="{message}", serialize=True)

    logger.translate(lambda message: message.title()).info("hello world")

    assert sink.json["text"] == "Hello World\n"
    assert sink.dict["message"] == sink.json["record"]["message"] == "Hello World"


def test_translate_updates_message_format_field(writer):
    logger.add(writer, format="{level.name}:{message}:{extra[user]}")

    logger.bind(user="Ada").translate(lambda message: message.swapcase()).info("Hello")

    assert writer.read() == "INFO:hELLO:Ada\n"
