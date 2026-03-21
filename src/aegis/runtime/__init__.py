"""Runtime engine, approval gates, and audit logging.

Main entry point::

    from aegis import Runtime
    from aegis.runtime.approval import AutoApprovalHandler, CLIApprovalHandler
    from aegis.runtime.approval_callback import CallbackApprovalHandler
    from aegis.runtime.approval_webhook import WebhookApprovalHandler
    from aegis.runtime.audit import AuditLogger
    from aegis.runtime.audit_logging import LoggingAuditLogger
    from aegis.runtime.audit_webhook import WebhookAuditLogger
"""

from aegis.runtime.approval import ApprovalHandler, AutoApprovalHandler, CLIApprovalHandler
from aegis.runtime.audit import AuditLogger
from aegis.runtime.engine import Runtime
from aegis.runtime.watcher import PolicyWatcher

__all__ = [
    "ApprovalHandler",
    "AuditLogger",
    "AutoApprovalHandler",
    "CLIApprovalHandler",
    "PolicyWatcher",
    "Runtime",
]
