import re

import pytest

from loguru import logger, redact


def make_record(message):
    return {"message": message}


def test_redact_returns_callable():
    patcher = redact()
    assert callable(patcher)


def test_redact_no_match_leaves_message_unchanged():
    patcher = redact()
    record = make_record("nothing secret here")
    patcher(record)
    assert record["message"] == "nothing secret here"


@pytest.mark.parametrize(
    "key",
    ["password", "passwd", "pwd", "pass", "PASSWORD", "Password"],
)
def test_redact_password_variants(key):
    patcher = redact()
    record = make_record("user logs in with " + key + "=hunter2 ok")
    patcher(record)
    assert record["message"] == "user logs in with " + key + "=[REDACTED] ok"


@pytest.mark.parametrize(
    "key",
    ["api_key", "apikey", "api-key", "secret", "client_secret", "CLIENT_SECRET"],
)
def test_redact_api_key_and_secret_variants(key):
    patcher = redact()
    record = make_record(key + "=abc123XYZ")
    patcher(record)
    assert record["message"] == key + "=[REDACTED]"


@pytest.mark.parametrize(
    "key",
    ["token", "access_token", "auth_token", "Access_Token"],
)
def test_redact_token_variants(key):
    patcher = redact()
    record = make_record(key + ": deadbeef")
    patcher(record)
    assert record["message"] == key + ": [REDACTED]"


def test_redact_colon_form():
    patcher = redact()
    record = make_record("password: hunter2")
    patcher(record)
    assert record["message"] == "password: [REDACTED]"


def test_redact_quoted_value():
    patcher = redact()
    record = make_record('password="hunter2"')
    patcher(record)
    assert record["message"] == 'password="[REDACTED]"'


def test_redact_single_quoted_value():
    patcher = redact()
    record = make_record("password: 'hunter2'")
    patcher(record)
    assert record["message"] == "password: '[REDACTED]'"


def test_redact_authorization_bearer():
    patcher = redact()
    record = make_record("Authorization: Bearer abc.def.ghi")
    patcher(record)
    assert record["message"] == "Authorization: Bearer [REDACTED]"


def test_redact_authorization_token():
    patcher = redact()
    record = make_record("Authorization: Token abc123")
    patcher(record)
    assert record["message"] == "Authorization: Token [REDACTED]"


def test_redact_authorization_case_insensitive():
    patcher = redact()
    record = make_record("authorization: bearer xyz")
    patcher(record)
    assert record["message"] == "authorization: bearer [REDACTED]"


def test_redact_multiple_secrets_in_one_message():
    patcher = redact()
    record = make_record("password=hunter2 api_key=abc123 token=xyz")
    patcher(record)
    assert record["message"] == "password=[REDACTED] api_key=[REDACTED] token=[REDACTED]"


def test_redact_does_not_match_substring_keys():
    # "passing" should not be treated as "pass"
    patcher = redact()
    record = make_record("passing=true")
    patcher(record)
    assert record["message"] == "passing=true"


def test_redact_extra_string_pattern_replaces_full_match():
    patcher = redact("AKIA[0-9A-Z]{16}")
    record = make_record("aws id=AKIAABCDEFGHIJKLMNOP done")
    patcher(record)
    assert record["message"] == "aws id=[REDACTED] done"


def test_redact_extra_string_pattern_is_case_insensitive():
    patcher = redact("custom-token-[a-z0-9]+")
    record = make_record("see CUSTOM-TOKEN-ABC123 here")
    patcher(record)
    assert record["message"] == "see [REDACTED] here"


def test_redact_extra_compiled_pattern_used_as_is():
    pattern = re.compile(r"SK-[A-Z]+")  # case-sensitive on purpose
    patcher = redact(pattern)
    record = make_record("SK-ABC and sk-xyz")
    patcher(record)
    # Only the upper-case variant is replaced because flags came from caller.
    assert record["message"] == "[REDACTED] and sk-xyz"


def test_redact_combines_builtins_and_extras():
    patcher = redact(r"AKIA[0-9A-Z]{16}")
    record = make_record(
        "password=hunter2 with id AKIAABCDEFGHIJKLMNOP and Authorization: Bearer xyz"
    )
    patcher(record)
    assert record["message"] == (
        "password=[REDACTED] with id [REDACTED] and Authorization: Bearer [REDACTED]"
    )


def test_redact_mutates_record_in_place_and_returns_none():
    patcher = redact()
    record = make_record("password=hunter2")
    result = patcher(record)
    assert result is None
    assert record["message"] == "password=[REDACTED]"


def test_redact_integrates_with_logger_patch(writer):
    logger.remove()
    logger.add(writer, format="{message}")
    patched = logger.patch(redact())
    patched.info("login password=hunter2 ok")
    assert writer.read() == "login password=[REDACTED] ok\n"
    logger.remove()
