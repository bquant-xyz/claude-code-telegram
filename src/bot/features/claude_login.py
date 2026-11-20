"""Relay ``claude auth login`` through Telegram.

The bot itself (python-telegram-bot) keeps running when the Claude CLI is
logged out, so an authorised user can re-authenticate remotely:

1. ``/login`` starts ``claude auth login`` in a pseudo-terminal and returns the
   sign-in URL the CLI prints. Its redirect is Anthropic's "copy this code"
   page, so it works from a phone.
2. ``/login <code>`` writes the code to the CLI prompt and reports the result.

Only the short-lived, single-use authorisation code passes through Telegram;
the resulting credentials are written by the CLI itself. The code is never
logged, and is redacted from any CLI output that is echoed back.
"""

import asyncio
import os
import pty
import re
import select
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional, Tuple

import structlog

logger = structlog.get_logger()

URL_RE = re.compile(r"https://\S+/oauth/authorize\?\S+")
PROMPT_RE = re.compile(r"paste code", re.IGNORECASE)
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*(\x07|\x1b\\)|\x1b[=>]")
# Authorisation codes are long URL-safe strings, optionally "<code>#<state>".
CODE_RE = re.compile(r"^[A-Za-z0-9._~#-]{20,512}$")

SESSION_TIMEOUT_S = 600.0
START_TIMEOUT_S = 30.0
SUBMIT_TIMEOUT_S = 60.0


def strip_ansi(text: str) -> str:
    """Remove terminal escape sequences and carriage returns."""
    return ANSI_RE.sub("", text).replace("\r", "")


def find_claude_cli(configured: Optional[str] = None) -> Optional[str]:
    """Locate the Claude CLI: configured path, PATH, then the SDK's bundled copy."""
    if configured and Path(configured).exists():
        return configured
    found = shutil.which("claude")
    if found:
        return found
    try:
        import claude_agent_sdk

        bundled = Path(claude_agent_sdk.__file__).parent / "_bundled" / "claude"
        if bundled.exists():
            return str(bundled)
    except ImportError:
        pass
    return None


class ClaudeLoginSession:
    """One ``claude auth login`` process running in a pseudo-terminal."""

    def __init__(self, cli_path: str, timeout_s: float = SESSION_TIMEOUT_S) -> None:
        self.cli_path = cli_path
        self.deadline = time.monotonic() + timeout_s
        self.proc: Optional[subprocess.Popen] = None  # type: ignore[type-arg]
        self.master_fd: Optional[int] = None
        self.output = ""

    @property
    def expired(self) -> bool:
        return time.monotonic() > self.deadline

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def _spawn(self) -> None:
        master, slave = pty.openpty()
        env = dict(os.environ)
        # Never try to open a local browser: the user signs in on their own device.
        env.update({"BROWSER": "/bin/false", "DISPLAY": "", "TERM": "dumb"})
        env.pop("WAYLAND_DISPLAY", None)
        self.proc = subprocess.Popen(
            [self.cli_path, "auth", "login"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            start_new_session=True,
            close_fds=True,
        )
        os.close(slave)
        self.master_fd = master

    def _read_until(self, pattern: "re.Pattern[str]", timeout_s: float) -> bool:
        """Read CLI output until ``pattern`` matches, the process exits or time runs out."""
        assert self.master_fd is not None
        end = time.monotonic() + timeout_s
        while time.monotonic() < end:
            if pattern.search(strip_ansi(self.output)):
                return True
            ready, _, _ = select.select([self.master_fd], [], [], 0.5)
            if ready:
                try:
                    chunk = os.read(self.master_fd, 65536)
                except OSError:  # EIO: the CLI closed the terminal
                    chunk = b""
                if not chunk:
                    break
                self.output += chunk.decode("utf-8", "replace")
            elif not self.alive:
                break
        return bool(pattern.search(strip_ansi(self.output)))

    def _start_blocking(self) -> str:
        self._spawn()
        if not self._read_until(PROMPT_RE, START_TIMEOUT_S):
            raise RuntimeError("the CLI did not show a sign-in prompt")
        match = URL_RE.search(strip_ansi(self.output))
        if not match:
            raise RuntimeError("no sign-in URL found in the CLI output")
        return match.group(0)

    async def start(self) -> str:
        """Start the CLI and return the sign-in URL."""
        try:
            return await asyncio.to_thread(self._start_blocking)
        except Exception:
            self.close()
            raise

    def _submit_blocking(self, code: str) -> Tuple[bool, str]:
        assert self.master_fd is not None and self.proc is not None
        mark = len(self.output)
        os.write(self.master_fd, code.encode() + b"\r")
        # Read until the CLI exits (it does after success or failure).
        self._read_until(re.compile(r"(?!x)x"), SUBMIT_TIMEOUT_S)
        try:
            rc = self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            rc = None
        tail = strip_ansi(self.output[mark:]).replace(code, "[code]")
        lines = [ln.strip() for ln in tail.splitlines() if ln.strip()]
        summary = "\n".join(lines[-5:])[:800]
        return rc == 0, summary

    async def submit(self, code: str) -> Tuple[bool, str]:
        """Send the authorisation code; return (success, redacted CLI output)."""
        try:
            return await asyncio.to_thread(self._submit_blocking, code)
        finally:
            self.close()

    def close(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=3)
            except (ProcessLookupError, PermissionError, subprocess.TimeoutExpired):
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None


async def auth_status(cli_path: str) -> Optional[bool]:
    """Return True/False from ``claude auth status``, or None if it can't be read."""
    import json

    try:
        proc = await asyncio.create_subprocess_exec(
            cli_path,
            "auth",
            "status",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        return bool(json.loads(out.decode()).get("loggedIn"))
    except Exception:
        return None


class ClaudeLoginManager:
    """Keeps at most one pending login per Telegram user."""

    def __init__(self) -> None:
        self._sessions: dict[int, ClaudeLoginSession] = {}

    def get(self, user_id: int) -> Optional[ClaudeLoginSession]:
        session = self._sessions.get(user_id)
        if session and (session.expired or not session.alive):
            self.cancel(user_id)
            return None
        return session

    def cancel(self, user_id: int) -> bool:
        session = self._sessions.pop(user_id, None)
        if session:
            session.close()
            return True
        return False

    async def start(self, user_id: int, cli_path: str) -> str:
        self.cancel(user_id)
        session = ClaudeLoginSession(cli_path)
        url = await session.start()
        self._sessions[user_id] = session
        return url

    async def submit(self, user_id: int, code: str) -> Tuple[bool, str]:
        session = self.get(user_id)
        if session is None:
            raise LookupError("no login in progress")
        self._sessions.pop(user_id, None)
        return await session.submit(code)


login_manager = ClaudeLoginManager()
