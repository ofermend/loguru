import io

import pytest

from loguru import logger
from loguru._i18n import _


class TestI18nUnit:
    """Direct unit tests for the ``_()`` translation helper."""

    def test_default_returns_english(self, monkeypatch):
        monkeypatch.delenv("LOGURU_LANG", raising=False)
        original = "Cannot log to objects of type '%s'"
        assert _(original) == original

    def test_fr_returns_french(self, monkeypatch):
        monkeypatch.setenv("LOGURU_LANG", "fr")
        original = "Cannot log to objects of type '%s'"
        result = _(original)
        assert result != original
        assert "%s" in result

    def test_unknown_lang_falls_back_to_english(self, monkeypatch):
        monkeypatch.setenv("LOGURU_LANG", "de")
        original = "Cannot log to objects of type '%s'"
        assert _(original) == original

    def test_unknown_string_returns_original(self, monkeypatch):
        monkeypatch.setenv("LOGURU_LANG", "fr")
        unknown = "this is a string not in the translation table"
        assert _(unknown) == unknown


class TestI18nIntegration:
    """End-to-end tests exercising ``_()`` through the public loguru API."""

    def test_logger_add_type_error_in_french(self, monkeypatch):
        logger.remove()
        monkeypatch.setenv("LOGURU_LANG", "fr")
        with pytest.raises(TypeError) as excinfo:
            logger.add(123)
        message = str(excinfo.value)
        assert message != "Cannot log to objects of type 'int'"
        assert "'int'" in message

    def test_logger_add_type_error_in_english(self, monkeypatch):
        logger.remove()
        monkeypatch.delenv("LOGURU_LANG", raising=False)
        with pytest.raises(TypeError, match=r"^Cannot log to objects of type 'int'$"):
            logger.add(123)

    def test_file_sink_error_in_french(self, monkeypatch, tmp_path):
        logger.remove()
        monkeypatch.setenv("LOGURU_LANG", "fr")
        with pytest.raises(ValueError, match=r"'bad rotation string'") as excinfo:
            logger.add(str(tmp_path / "out.log"), rotation="bad rotation string")
        message = str(excinfo.value)
        assert message != "Cannot parse rotation from: 'bad rotation string'"

    def test_catch_default_message_in_french(self, monkeypatch):
        logger.remove()
        monkeypatch.setenv("LOGURU_LANG", "fr")
        sink = io.StringIO()
        logger.add(sink, format="{message}", colorize=False)

        @logger.catch
        def boom():
            raise ValueError("test")

        boom()
        output = sink.getvalue()
        assert "An error has been caught in function" not in output
        assert "ValueError: test" in output
