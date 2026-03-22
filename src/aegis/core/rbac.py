"""Role-Based Access Control (RBAC) for Aegis policy management.

Provides fine-grained permission checks for enterprise policy lifecycle:
view, edit, deploy, delete policies plus audit and compliance operations.

Thread-safe: all user/role mutations are guarded by a reentrant lock.
"""

from __future__ import annotations

import enum
import threading
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


class Permission(enum.Enum):
    """Granular permissions for Aegis operations."""

    POLICY_VIEW = "policy:view"
    POLICY_EDIT = "policy:edit"
    POLICY_DEPLOY = "policy:deploy"
    POLICY_DELETE = "policy:delete"
    AUDIT_VIEW = "audit:view"
    AUDIT_EXPORT = "audit:export"
    AUDIT_VERIFY = "audit:verify"
    COMPLIANCE_VIEW = "compliance:view"
    COMPLIANCE_GENERATE = "compliance:generate"
    AGENT_MANAGE = "agent:manage"
    WEBHOOK_MANAGE = "webhook:manage"
    ADMIN = "admin"


_ALL_PERMISSIONS: frozenset[Permission] = frozenset(Permission)

# ---------------------------------------------------------------------------
# Role
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Role:
    """Named collection of permissions.

    Attributes:
        name: Unique role identifier (lowercase, no spaces).
        description: Human-readable explanation.
        permissions: Immutable set of granted permissions.
    """

    name: str
    description: str
    permissions: frozenset[Permission]


# ---------------------------------------------------------------------------
# Built-in roles (hierarchical: each level includes the previous)
# ---------------------------------------------------------------------------

_VIEWER_PERMS: frozenset[Permission] = frozenset(
    {
        Permission.POLICY_VIEW,
        Permission.AUDIT_VIEW,
        Permission.COMPLIANCE_VIEW,
    }
)

_OPERATOR_PERMS: frozenset[Permission] = _VIEWER_PERMS | frozenset(
    {
        Permission.AUDIT_EXPORT,
        Permission.AUDIT_VERIFY,
        Permission.COMPLIANCE_GENERATE,
    }
)

_EDITOR_PERMS: frozenset[Permission] = _OPERATOR_PERMS | frozenset(
    {
        Permission.POLICY_EDIT,
    }
)

_DEPLOYER_PERMS: frozenset[Permission] = _EDITOR_PERMS | frozenset(
    {
        Permission.POLICY_DEPLOY,
        Permission.POLICY_DELETE,
    }
)

BUILT_IN_ROLES: dict[str, Role] = {
    "viewer": Role(
        name="viewer",
        description="Read-only access to policies, audits, and compliance reports.",
        permissions=_VIEWER_PERMS,
    ),
    "operator": Role(
        name="operator",
        description="Viewer permissions plus audit export/verify and compliance generation.",
        permissions=_OPERATOR_PERMS,
    ),
    "editor": Role(
        name="editor",
        description="Operator permissions plus policy editing.",
        permissions=_EDITOR_PERMS,
    ),
    "deployer": Role(
        name="deployer",
        description="Editor permissions plus policy deployment and deletion.",
        permissions=_DEPLOYER_PERMS,
    ),
    "admin": Role(
        name="admin",
        description="Full access to all Aegis operations.",
        permissions=_ALL_PERMISSIONS,
    ),
}

# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class User:
    """An identity that can be assigned roles and direct permissions.

    Attributes:
        user_id: Unique identifier.
        name: Display name.
        email: Contact email.
        roles: Set of role names assigned to this user.
        extra_permissions: Permissions granted directly (bypass roles).
    """

    user_id: str
    name: str
    email: str
    roles: frozenset[str] = field(default_factory=frozenset)
    extra_permissions: frozenset[Permission] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# AccessDecision
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AccessDecision:
    """Result of an access check.

    Attributes:
        allowed: Whether the action is permitted.
        user_id: The user who was checked.
        permission: The permission that was checked.
        granted_by: How the permission was granted, e.g.
            ``"role:admin"`` or ``"direct:policy:view"``.
        reason: Human-readable explanation.
    """

    allowed: bool
    user_id: str
    permission: Permission
    granted_by: str
    reason: str


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AccessDeniedError(Exception):
    """Raised when a required permission is not satisfied."""

    def __init__(self, user_id: str, permission: Permission, reason: str) -> None:
        self.user_id = user_id
        self.permission = permission
        self.reason = reason
        super().__init__(f"Access denied for user '{user_id}': {permission.value} — {reason}")


# ---------------------------------------------------------------------------
# AccessController
# ---------------------------------------------------------------------------


class AccessController:
    """Central authority for permission checks.

    All public methods are thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._roles: dict[str, Role] = dict(BUILT_IN_ROLES)
        self._users: dict[str, User] = {}

    # -- Role management ----------------------------------------------------

    def add_role(self, role: Role) -> None:
        """Register a custom role."""
        with self._lock:
            self._roles[role.name] = role

    # -- User management ----------------------------------------------------

    def add_user(self, user: User) -> None:
        """Register a user."""
        with self._lock:
            self._users[user.user_id] = user

    def remove_user(self, user_id: str) -> None:
        """Remove a user. Raises ``KeyError`` if not found."""
        with self._lock:
            if user_id not in self._users:
                raise KeyError(f"User '{user_id}' not found")
            del self._users[user_id]

    # -- Permission checks --------------------------------------------------

    def check(self, user_id: str, permission: Permission) -> AccessDecision:
        """Evaluate whether *user_id* holds *permission*.

        Returns an :class:`AccessDecision` regardless of outcome.
        """
        with self._lock:
            user = self._users.get(user_id)
            if user is None:
                return AccessDecision(
                    allowed=False,
                    user_id=user_id,
                    permission=permission,
                    granted_by="",
                    reason=f"User '{user_id}' not found",
                )

            # 1) Check direct (extra) permissions first
            if permission in user.extra_permissions:
                return AccessDecision(
                    allowed=True,
                    user_id=user_id,
                    permission=permission,
                    granted_by=f"direct:{permission.value}",
                    reason=f"Directly granted {permission.value}",
                )

            # 2) Check role-based permissions
            for role_name in sorted(user.roles):
                role = self._roles.get(role_name)
                if role is not None and permission in role.permissions:
                    return AccessDecision(
                        allowed=True,
                        user_id=user_id,
                        permission=permission,
                        granted_by=f"role:{role_name}",
                        reason=f"Granted via role '{role_name}'",
                    )

            return AccessDecision(
                allowed=False,
                user_id=user_id,
                permission=permission,
                granted_by="",
                reason=f"No role or direct grant provides {permission.value}",
            )

    def require(self, user_id: str, permission: Permission) -> None:
        """Assert *user_id* holds *permission*; raise on denial."""
        decision = self.check(user_id, permission)
        if not decision.allowed:
            raise AccessDeniedError(user_id, permission, decision.reason)

    # -- Role / permission grants -------------------------------------------

    def grant_role(self, user_id: str, role_name: str) -> None:
        """Add *role_name* to a user's role set."""
        with self._lock:
            user = self._users.get(user_id)
            if user is None:
                raise KeyError(f"User '{user_id}' not found")
            if role_name not in self._roles:
                raise KeyError(f"Role '{role_name}' not found")
            self._users[user_id] = User(
                user_id=user.user_id,
                name=user.name,
                email=user.email,
                roles=user.roles | frozenset({role_name}),
                extra_permissions=user.extra_permissions,
            )

    def revoke_role(self, user_id: str, role_name: str) -> None:
        """Remove *role_name* from a user's role set."""
        with self._lock:
            user = self._users.get(user_id)
            if user is None:
                raise KeyError(f"User '{user_id}' not found")
            self._users[user_id] = User(
                user_id=user.user_id,
                name=user.name,
                email=user.email,
                roles=user.roles - frozenset({role_name}),
                extra_permissions=user.extra_permissions,
            )

    def grant_permission(self, user_id: str, permission: Permission) -> None:
        """Grant a direct permission to a user."""
        with self._lock:
            user = self._users.get(user_id)
            if user is None:
                raise KeyError(f"User '{user_id}' not found")
            self._users[user_id] = User(
                user_id=user.user_id,
                name=user.name,
                email=user.email,
                roles=user.roles,
                extra_permissions=user.extra_permissions | frozenset({permission}),
            )

    # -- Query helpers ------------------------------------------------------

    def get_user_permissions(self, user_id: str) -> frozenset[Permission]:
        """Return the effective permission set for *user_id*."""
        with self._lock:
            user = self._users.get(user_id)
            if user is None:
                raise KeyError(f"User '{user_id}' not found")
            perms: set[Permission] = set(user.extra_permissions)
            for role_name in user.roles:
                role = self._roles.get(role_name)
                if role is not None:
                    perms |= role.permissions
            return frozenset(perms)

    def get_users_with_permission(self, permission: Permission) -> list[User]:
        """Return all registered users who hold *permission*."""
        with self._lock:
            result: list[User] = []
            for user in self._users.values():
                if permission in user.extra_permissions:
                    result.append(user)
                    continue
                for role_name in user.roles:
                    role = self._roles.get(role_name)
                    if role is not None and permission in role.permissions:
                        result.append(user)
                        break
            return result
