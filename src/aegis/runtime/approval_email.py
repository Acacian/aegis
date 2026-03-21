"""Email-based approval notification handler.

Sends a formatted email with action details using Python's built-in
``smtplib`` and ``email`` modules — no extra dependencies needed.

Since email is inherently asynchronous, the handler sends the notification
and returns a configurable default (``default_approved``, defaults to False).

Example::

    handler = EmailApprovalHandler(
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        sender="aegis@example.com",
        recipient="admin@example.com",
        username="aegis@example.com",
        password="app-password",
    )
    runtime = Runtime(executor=..., policy=..., approval_handler=handler)
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from aegis.core.policy import PolicyDecision
from aegis.runtime.approval import ApprovalHandler

logger = logging.getLogger(__name__)

_RISK_COLOR = {
    "LOW": "#2ecc71",
    "MEDIUM": "#f1c40f",
    "HIGH": "#e67e22",
    "CRITICAL": "#e74c3c",
}


def _build_html(
    decision: PolicyDecision,
    approve_url: str | None = None,
    deny_url: str | None = None,
) -> str:
    """Build HTML email body for the approval notification."""
    risk_name = decision.risk_level.name
    color = _RISK_COLOR.get(risk_name, "#95a5a6")

    rows = [
        ("Action", decision.action.type),
        ("Target", decision.action.target),
        ("Risk Level", risk_name),
        ("Matched Rule", decision.matched_rule),
    ]
    if decision.action.description:
        rows.append(("Description", decision.action.description))
    if decision.action.params:
        rows.append(("Parameters", str(decision.action.params)))

    table_rows = "".join(
        f"<tr><td style='padding:6px 12px;font-weight:bold;'>{k}</td>"
        f"<td style='padding:6px 12px;'>{v}</td></tr>"
        for k, v in rows
    )

    buttons = ""
    if approve_url or deny_url:
        parts: list[str] = []
        if approve_url:
            parts.append(
                f'<a href="{approve_url}" style="background:#2ecc71;color:#fff;'
                f"padding:10px 24px;text-decoration:none;border-radius:4px;"
                f'margin-right:12px;">Approve</a>'
            )
        if deny_url:
            parts.append(
                f'<a href="{deny_url}" style="background:#e74c3c;color:#fff;'
                f'padding:10px 24px;text-decoration:none;border-radius:4px;">Deny</a>'
            )
        buttons = '<div style="margin-top:20px;text-align:center;">' + "".join(parts) + "</div>"

    return f"""<html><body style="font-family:sans-serif;padding:20px;">
<h2 style="color:{color};">Aegis Approval Required</h2>
<table style="border-collapse:collapse;border:1px solid #ddd;">{table_rows}</table>
{buttons}
<p style="color:#888;font-size:12px;margin-top:24px;">
Sent by Aegis Policy Engine</p>
</body></html>"""


def _build_plain(
    decision: PolicyDecision,
    approve_url: str | None = None,
    deny_url: str | None = None,
) -> str:
    """Build plain text email body."""
    lines = [
        "AEGIS APPROVAL REQUIRED",
        "=" * 40,
        f"Action:  {decision.action.type}",
        f"Target:  {decision.action.target}",
        f"Risk:    {decision.risk_level.name}",
        f"Rule:    {decision.matched_rule}",
    ]
    if decision.action.description:
        lines.append(f"Desc:    {decision.action.description}")
    if decision.action.params:
        lines.append(f"Params:  {decision.action.params}")

    if approve_url:
        lines.extend(["", f"Approve: {approve_url}"])
    if deny_url:
        lines.append(f"Deny:    {deny_url}")

    return "\n".join(lines)


class EmailApprovalHandler(ApprovalHandler):
    """Send an approval notification email and return a configurable default.

    Since email is inherently asynchronous (the recipient reads and responds
    on their own time), this handler sends the notification and immediately
    returns ``default_approved``.  For a full approve/deny flow, provide
    ``approve_url`` / ``deny_url`` links that point to a webhook endpoint.

    Args:
        smtp_host: SMTP server hostname.
        smtp_port: SMTP server port.
        sender: Sender email address.
        recipient: Recipient email address.
        username: SMTP authentication username (optional).
        password: SMTP authentication password (optional).
        use_tls: Whether to use STARTTLS (default True).
        timeout: SMTP connection timeout in seconds (default 300).
        approve_url: Optional URL for the approve action link.
        deny_url: Optional URL for the deny action link.
        default_approved: Value to return after sending (default False).
    """

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        sender: str,
        recipient: str,
        *,
        username: str | None = None,
        password: str | None = None,
        use_tls: bool = True,
        timeout: float = 300.0,
        approve_url: str | None = None,
        deny_url: str | None = None,
        default_approved: bool = False,
    ) -> None:
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._sender = sender
        self._recipient = recipient
        self._username = username
        self._password = password
        self._use_tls = use_tls
        self._timeout = timeout
        self._approve_url = approve_url
        self._deny_url = deny_url
        self._default_approved = default_approved

    def _build_message(self, decision: PolicyDecision) -> MIMEMultipart:
        """Construct the MIME email message."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = (
            f"[Aegis] Approval Required: {decision.action.type} "
            f"-> {decision.action.target} ({decision.risk_level.name})"
        )
        msg["From"] = self._sender
        msg["To"] = self._recipient

        plain = _build_plain(decision, self._approve_url, self._deny_url)
        html = _build_html(decision, self._approve_url, self._deny_url)

        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(html, "html"))
        return msg

    def _send_sync(self, msg: MIMEMultipart) -> None:
        """Send the email synchronously (called in a thread)."""
        smtp: smtplib.SMTP | smtplib.SMTP_SSL
        if self._use_tls:
            smtp = smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=int(self._timeout))
            smtp.starttls()
        else:
            smtp = smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=int(self._timeout))

        try:
            if self._username and self._password:
                smtp.login(self._username, self._password)
            smtp.sendmail(self._sender, [self._recipient], msg.as_string())
        finally:
            smtp.quit()

    async def request_approval(self, decision: PolicyDecision) -> bool:
        """Send approval notification email and return the default decision.

        The email is sent in a thread pool to avoid blocking the event loop.
        On any failure, returns False (deny by default).
        """
        msg = self._build_message(decision)

        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._send_sync, msg)
            logger.info(
                "Approval email sent to %s for %s -> %s",
                self._recipient,
                decision.action.type,
                decision.action.target,
            )
        except Exception:
            logger.exception("Failed to send approval email")
            return False

        return self._default_approved
