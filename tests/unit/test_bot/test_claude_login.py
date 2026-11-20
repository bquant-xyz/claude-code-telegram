"""Tests for the /login relay of ``claude auth login`` and log token redaction."""

import asyncio
import logging
import os
import sys
import textwrap
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.bot.features import claude_login
from src.bot.features.claude_login import (
    ClaudeLoginManager,
    ClaudeLoginSession,
    redact_code,
    strip_ansi,
)
from src.bot.handlers.command import login_command
from src.bot.middleware.security import is_login_command
from src.main import RedactTelegramTokenFilter, setup_logging

GOOD_CODE = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789#state-value_123"
URL = (
    "https://claude.com/cai/oauth/authorize?code=true&client_id=abc"
    "&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback"
)


@pytest.fixture
def fake_cli(tmp_path):
    """A stand-in for ``claude`` that mimics the ``auth login`` prompt."""
    script = tmp_path / "claude"
    script.write_text(
        f"#!{sys.executable}\n"
        + textwrap.dedent(
            f"""
            import sys
            if sys.argv[1:] == ["auth", "status"]:
                print('{{"loggedIn": true}}')
                sys.exit(0)
            print("\\x1b[1mOpening browser to sign in...\\x1b[0m")
            print("If the browser didn't open, visit: {URL}")
            sys.stdout.write("Paste code here if prompted > ")
            sys.stdout.flush()
            code = sys.stdin.readline().strip()
            print(code)  # terminals echo the pasted code
            if code == "{GOOD_CODE}":
                print("Login successful.")
                sys.exit(0)
            print("OAuth error: invalid code")
            sys.exit(1)
            """
        )
    )
    script.chmod(0o755)
    return str(script)


def test_strip_ansi():
    assert strip_ansi("\x1b[1mhi\x1b[0m\r\n") == "hi\n"


@pytest.mark.parametrize(
    "text,expected",
    [
        ("/login", True),
        ("/login abc#def", True),
        ("/login@MyBot abc", True),
        ("  /LOGIN x", True),
        ("/loginx", False),
        ("please /login", False),
        ("", False),
    ],
)
def test_is_login_command(text, expected):
    assert is_login_command(text) is expected


async def test_session_success_redacts_code(fake_cli):
    session = ClaudeLoginSession(fake_cli)
    assert await session.start() == URL
    ok, output = await session.submit(GOOD_CODE)
    assert ok
    assert "Login successful" in output
    assert GOOD_CODE not in output
    assert not session.alive


async def test_session_failure(fake_cli):
    session = ClaudeLoginSession(fake_cli)
    await session.start()
    ok, output = await session.submit("Z" * 30)
    assert not ok
    assert "invalid code" in output


async def test_session_start_fails_without_prompt(tmp_path):
    script = tmp_path / "claude"
    script.write_text(f"#!{sys.executable}\nprint('nothing useful')\n")
    script.chmod(0o755)
    session = ClaudeLoginSession(str(script))
    with pytest.raises(RuntimeError):
        await session.start()
    assert not session.alive


async def test_manager_submit_without_session():
    with pytest.raises(LookupError):
        await ClaudeLoginManager().submit(1, GOOD_CODE)


async def test_manager_expiry_and_cancel(fake_cli):
    manager = ClaudeLoginManager()
    await manager.start(1, fake_cli)
    assert await manager.get(1) is not None
    manager._sessions[1].deadline = 0  # force expiry
    assert await manager.get(1) is None
    await manager.start(1, fake_cli)
    assert await manager.cancel(1) is True
    assert await manager.cancel(1) is False


async def test_auth_status(fake_cli):
    assert await claude_login.auth_status(fake_cli) is True


def _update_and_context(args, chat_type="private", edited=False):
    message = MagicMock()
    message.reply_text = AsyncMock()
    message.delete = AsyncMock()
    update = SimpleNamespace(
        message=None if edited else message,
        edited_message=message if edited else None,
        effective_message=message,
        effective_user=SimpleNamespace(id=42),
        effective_chat=SimpleNamespace(id=99, type=chat_type),
    )
    audit = MagicMock()
    audit.log_command = AsyncMock()
    context = SimpleNamespace(
        args=args,
        bot=SimpleNamespace(send_message=AsyncMock()),
        bot_data={"audit_logger": audit, "settings": None},
    )
    return update, context, audit


async def test_login_command_flow(fake_cli):
    manager = ClaudeLoginManager()
    with (
        patch.object(claude_login, "login_manager", manager),
        patch.object(claude_login, "find_claude_cli", return_value=fake_cli),
    ):
        update, context, audit = _update_and_context([])
        await login_command(update, context)
        sent = update.message.reply_text.call_args.args[0]
        assert "sign-in link" in sent and "claude.com/cai/oauth/authorize" in sent

        update, context, audit = _update_and_context([GOOD_CODE])
        await login_command(update, context)
        update.message.delete.assert_awaited_once()
        final = context.bot.send_message.call_args.kwargs["text"]
        assert "succeeded" in final
        for call in audit.log_command.call_args_list:
            assert GOOD_CODE not in repr(call)


async def test_login_command_rejects_group_chat():
    update, context, _ = _update_and_context([], chat_type="group")
    await login_command(update, context)
    assert "private chat" in update.message.reply_text.call_args.args[0]


async def test_login_command_code_without_session(fake_cli):
    with (
        patch.object(claude_login, "login_manager", ClaudeLoginManager()),
        patch.object(claude_login, "find_claude_cli", return_value=fake_cli),
    ):
        update, context, _ = _update_and_context([GOOD_CODE])
        await login_command(update, context)
        update.message.delete.assert_awaited_once()
        assert (
            "No login in progress" in context.bot.send_message.call_args.kwargs["text"]
        )


def test_redact_filter_masks_token():
    token_url = (
        "https://api.telegram.org/bot12345:FAKEabcdefghijklmnopqrstuvwxyz/getUpdates"
    )
    record = logging.LogRecord(
        "httpx", logging.INFO, "", 0, "HTTP Request: POST %s", (token_url,), None
    )
    RedactTelegramTokenFilter().filter(record)
    assert "FAKEabcdef" not in record.getMessage()
    assert "bot<redacted>/getUpdates" in record.getMessage()


def test_setup_logging_quiets_httpx():
    setup_logging(debug=False)
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert any(
        isinstance(f, RedactTelegramTokenFilter)
        for h in logging.getLogger().handlers
        for f in h.filters
    )


async def test_manager_expiry_timer_kills_session(fake_cli):
    manager = ClaudeLoginManager(timeout_s=0.3)
    await manager.start(1, fake_cli)
    session = manager._sessions[1]
    await asyncio.sleep(0.6)  # no further /login: the timer alone must clean up
    for _ in range(50):
        if not manager._tasks:
            break
        await asyncio.sleep(0.1)
    assert 1 not in manager._sessions
    assert not session.alive and session.master_fd is None


def _open_fds():
    return len(os.listdir("/proc/self/fd"))


async def test_spawn_failure_closes_fds(tmp_path):
    not_exec = tmp_path / "claude"
    not_exec.write_text("not executable")
    before = _open_fds()
    for _ in range(5):
        with pytest.raises(OSError):
            await ClaudeLoginSession(str(not_exec)).start()
    assert _open_fds() == before


async def test_session_without_url_fails(tmp_path):
    script = tmp_path / "claude"
    script.write_text(
        f"#!{sys.executable}\nimport sys\n"
        "sys.stdout.write('Paste code here if prompted > '); sys.stdout.flush()\n"
        "sys.stdin.readline()\n"
    )
    script.chmod(0o755)
    session = ClaudeLoginSession(str(script))
    with pytest.raises(RuntimeError, match="URL"):
        await session.start()
    assert not session.alive


def test_redact_code_hides_split_echo():
    out = (
        f"Paste code > {GOOD_CODE[:15]}\x1b[K\n{GOOD_CODE[15:]}\nOAuth error: bad code"
    )
    redacted = redact_code(out, GOOD_CODE)
    assert "OAuth error: bad code" in redacted
    assert GOOD_CODE[:15] not in redacted and GOOD_CODE[15:30] not in redacted


def test_redact_filter_survives_bad_args():
    record = logging.LogRecord(
        "x",
        logging.WARNING,
        "",
        0,
        "%s %s bot12345:FAKEabcdefghijklmnopqrstuvwxyz",
        ("a",),
        None,
    )
    assert RedactTelegramTokenFilter().filter(record) is True
    assert "FAKEabcdef" not in str(record.msg)


async def test_login_command_ignores_edited_message(fake_cli):
    with patch.object(claude_login, "login_manager", ClaudeLoginManager()):
        update, context, _ = _update_and_context([GOOD_CODE], edited=True)
        await login_command(update, context)
        update.effective_message.delete.assert_awaited_once()
        assert "ignored" in context.bot.send_message.call_args.kwargs["text"]


async def test_login_command_delete_failure_warns(fake_cli):
    with (
        patch.object(claude_login, "login_manager", ClaudeLoginManager()),
        patch.object(claude_login, "find_claude_cli", return_value=fake_cli),
    ):
        update, context, _ = _update_and_context([GOOD_CODE])
        update.message.delete.side_effect = RuntimeError("too old")
        await login_command(update, context)
        texts = [c.kwargs["text"] for c in context.bot.send_message.call_args_list]
        assert any("Could not delete" in t for t in texts)


async def test_login_success_trusts_auth_status(fake_cli):
    manager = ClaudeLoginManager()
    with (
        patch.object(claude_login, "login_manager", manager),
        patch.object(claude_login, "find_claude_cli", return_value=fake_cli),
        patch.object(manager, "submit", AsyncMock(return_value=(False, "slow exit"))),
        patch.object(claude_login, "auth_status", AsyncMock(return_value=True)),
    ):
        update, context, _ = _update_and_context([GOOD_CODE])
        await login_command(update, context)
        assert "succeeded" in context.bot.send_message.call_args.kwargs["text"]
