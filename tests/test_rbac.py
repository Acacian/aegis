"""Tests for the Role-Based Access Control (RBAC) system."""

from __future__ import annotations

import concurrent.futures
import threading

import pytest

from aegis.core.rbac import (
    BUILT_IN_ROLES,
    AccessController,
    AccessDecision,
    AccessDeniedError,
    Permission,
    Role,
    User,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user(
    user_id: str = "u1",
    name: str = "Alice",
    email: str = "alice@example.com",
    roles: frozenset[str] | None = None,
    extra_permissions: frozenset[Permission] | None = None,
) -> User:
    return User(
        user_id=user_id,
        name=name,
        email=email,
        roles=roles or frozenset(),
        extra_permissions=extra_permissions or frozenset(),
    )


# ===================================================================
# Built-in roles
# ===================================================================


class TestBuiltInRoles:
    """Verify that pre-defined roles expose the correct permissions."""

    def test_viewer_permissions(self) -> None:
        viewer = BUILT_IN_ROLES["viewer"]
        assert Permission.POLICY_VIEW in viewer.permissions
        assert Permission.AUDIT_VIEW in viewer.permissions
        assert Permission.COMPLIANCE_VIEW in viewer.permissions
        assert len(viewer.permissions) == 3

    def test_operator_includes_viewer(self) -> None:
        operator = BUILT_IN_ROLES["operator"]
        viewer = BUILT_IN_ROLES["viewer"]
        assert viewer.permissions < operator.permissions

    def test_operator_extra_permissions(self) -> None:
        op = BUILT_IN_ROLES["operator"]
        assert Permission.AUDIT_EXPORT in op.permissions
        assert Permission.AUDIT_VERIFY in op.permissions
        assert Permission.COMPLIANCE_GENERATE in op.permissions

    def test_editor_includes_operator(self) -> None:
        editor = BUILT_IN_ROLES["editor"]
        operator = BUILT_IN_ROLES["operator"]
        assert operator.permissions < editor.permissions

    def test_editor_has_policy_edit(self) -> None:
        assert Permission.POLICY_EDIT in BUILT_IN_ROLES["editor"].permissions

    def test_deployer_includes_editor(self) -> None:
        deployer = BUILT_IN_ROLES["deployer"]
        editor = BUILT_IN_ROLES["editor"]
        assert editor.permissions < deployer.permissions

    def test_deployer_has_deploy_and_delete(self) -> None:
        deployer = BUILT_IN_ROLES["deployer"]
        assert Permission.POLICY_DEPLOY in deployer.permissions
        assert Permission.POLICY_DELETE in deployer.permissions

    def test_admin_has_all_permissions(self) -> None:
        admin = BUILT_IN_ROLES["admin"]
        for perm in Permission:
            assert perm in admin.permissions

    def test_admin_permission_count(self) -> None:
        admin = BUILT_IN_ROLES["admin"]
        assert len(admin.permissions) == len(Permission)

    def test_built_in_role_names(self) -> None:
        assert set(BUILT_IN_ROLES.keys()) == {
            "viewer",
            "operator",
            "editor",
            "deployer",
            "admin",
        }


# ===================================================================
# User / AccessDecision dataclasses
# ===================================================================


class TestDataclasses:
    def test_user_defaults(self) -> None:
        u = User(user_id="x", name="X", email="x@x.com")
        assert u.roles == frozenset()
        assert u.extra_permissions == frozenset()

    def test_user_frozen(self) -> None:
        u = _make_user()
        with pytest.raises(AttributeError):
            u.name = "Bob"  # type: ignore[misc]

    def test_role_frozen(self) -> None:
        r = Role(name="r", description="d", permissions=frozenset())
        with pytest.raises(AttributeError):
            r.name = "other"  # type: ignore[misc]

    def test_access_decision_fields(self) -> None:
        d = AccessDecision(
            allowed=True,
            user_id="u1",
            permission=Permission.ADMIN,
            granted_by="role:admin",
            reason="ok",
        )
        assert d.allowed is True
        assert d.granted_by == "role:admin"


# ===================================================================
# AccessController — user management
# ===================================================================


class TestUserManagement:
    def test_add_and_remove_user(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user())
        ac.remove_user("u1")
        decision = ac.check("u1", Permission.POLICY_VIEW)
        assert decision.allowed is False

    def test_remove_unknown_user_raises(self) -> None:
        ac = AccessController()
        with pytest.raises(KeyError, match="not found"):
            ac.remove_user("ghost")

    def test_add_user_replaces(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user(name="Alice"))
        ac.add_user(_make_user(name="Alice2"))
        # Still works — latest wins
        decision = ac.check("u1", Permission.POLICY_VIEW)
        assert decision.allowed is False  # no roles yet


# ===================================================================
# AccessController.check
# ===================================================================


class TestCheck:
    def test_check_unknown_user_denied(self) -> None:
        ac = AccessController()
        decision = ac.check("nope", Permission.POLICY_VIEW)
        assert decision.allowed is False
        assert "not found" in decision.reason

    def test_viewer_can_view(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user(roles=frozenset({"viewer"})))
        decision = ac.check("u1", Permission.POLICY_VIEW)
        assert decision.allowed is True
        assert decision.granted_by == "role:viewer"

    def test_viewer_cannot_edit(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user(roles=frozenset({"viewer"})))
        decision = ac.check("u1", Permission.POLICY_EDIT)
        assert decision.allowed is False

    def test_admin_can_do_anything(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user(roles=frozenset({"admin"})))
        for perm in Permission:
            assert ac.check("u1", perm).allowed is True

    def test_direct_permission_check(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user(extra_permissions=frozenset({Permission.WEBHOOK_MANAGE})))
        decision = ac.check("u1", Permission.WEBHOOK_MANAGE)
        assert decision.allowed is True
        assert decision.granted_by == "direct:webhook:manage"

    def test_direct_takes_precedence_over_role(self) -> None:
        """Direct grants are checked first, so granted_by should say 'direct'."""
        ac = AccessController()
        ac.add_user(
            _make_user(
                roles=frozenset({"viewer"}),
                extra_permissions=frozenset({Permission.POLICY_VIEW}),
            )
        )
        decision = ac.check("u1", Permission.POLICY_VIEW)
        assert decision.granted_by.startswith("direct:")


# ===================================================================
# AccessController.require
# ===================================================================


class TestRequire:
    def test_require_passes_when_allowed(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user(roles=frozenset({"admin"})))
        ac.require("u1", Permission.ADMIN)  # should not raise

    def test_require_raises_access_denied(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user())
        with pytest.raises(AccessDeniedError) as exc_info:
            ac.require("u1", Permission.POLICY_DEPLOY)
        err = exc_info.value
        assert err.user_id == "u1"
        assert err.permission == Permission.POLICY_DEPLOY

    def test_access_denied_error_message(self) -> None:
        err = AccessDeniedError("u1", Permission.ADMIN, "nope")
        assert "u1" in str(err)
        assert "admin" in str(err)


# ===================================================================
# grant_role / revoke_role
# ===================================================================


class TestRoleGrants:
    def test_grant_role(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user())
        ac.grant_role("u1", "editor")
        assert ac.check("u1", Permission.POLICY_EDIT).allowed is True

    def test_revoke_role(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user(roles=frozenset({"editor"})))
        ac.revoke_role("u1", "editor")
        assert ac.check("u1", Permission.POLICY_EDIT).allowed is False

    def test_grant_role_unknown_user_raises(self) -> None:
        ac = AccessController()
        with pytest.raises(KeyError):
            ac.grant_role("ghost", "viewer")

    def test_grant_role_unknown_role_raises(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user())
        with pytest.raises(KeyError, match="Role.*not found"):
            ac.grant_role("u1", "superadmin")

    def test_revoke_role_unknown_user_raises(self) -> None:
        ac = AccessController()
        with pytest.raises(KeyError):
            ac.revoke_role("ghost", "viewer")

    def test_revoke_nonexistent_role_is_noop(self) -> None:
        """Revoking a role the user doesn't have should not error."""
        ac = AccessController()
        ac.add_user(_make_user())
        ac.revoke_role("u1", "admin")  # not assigned, no error


# ===================================================================
# grant_permission
# ===================================================================


class TestGrantPermission:
    def test_grant_direct_permission(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user())
        ac.grant_permission("u1", Permission.AGENT_MANAGE)
        assert ac.check("u1", Permission.AGENT_MANAGE).allowed is True

    def test_grant_permission_unknown_user_raises(self) -> None:
        ac = AccessController()
        with pytest.raises(KeyError):
            ac.grant_permission("ghost", Permission.ADMIN)


# ===================================================================
# get_user_permissions
# ===================================================================


class TestGetUserPermissions:
    def test_aggregates_roles_and_direct(self) -> None:
        ac = AccessController()
        ac.add_user(
            _make_user(
                roles=frozenset({"viewer"}),
                extra_permissions=frozenset({Permission.WEBHOOK_MANAGE}),
            )
        )
        perms = ac.get_user_permissions("u1")
        assert Permission.POLICY_VIEW in perms
        assert Permission.WEBHOOK_MANAGE in perms

    def test_multiple_roles_union(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user(roles=frozenset({"viewer", "operator"})))
        perms = ac.get_user_permissions("u1")
        assert Permission.AUDIT_EXPORT in perms
        assert Permission.POLICY_VIEW in perms

    def test_unknown_user_raises(self) -> None:
        ac = AccessController()
        with pytest.raises(KeyError):
            ac.get_user_permissions("nope")


# ===================================================================
# get_users_with_permission
# ===================================================================


class TestGetUsersWithPermission:
    def test_filters_correctly(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user(user_id="u1", roles=frozenset({"viewer"})))
        ac.add_user(_make_user(user_id="u2", roles=frozenset({"editor"})))
        users = ac.get_users_with_permission(Permission.POLICY_EDIT)
        assert len(users) == 1
        assert users[0].user_id == "u2"

    def test_includes_direct_grants(self) -> None:
        ac = AccessController()
        ac.add_user(
            _make_user(
                user_id="u1",
                extra_permissions=frozenset({Permission.AGENT_MANAGE}),
            )
        )
        users = ac.get_users_with_permission(Permission.AGENT_MANAGE)
        assert len(users) == 1

    def test_returns_empty_when_nobody_has_permission(self) -> None:
        ac = AccessController()
        ac.add_user(_make_user(user_id="u1"))
        assert ac.get_users_with_permission(Permission.ADMIN) == []


# ===================================================================
# Custom roles
# ===================================================================


class TestCustomRoles:
    def test_add_custom_role(self) -> None:
        ac = AccessController()
        custom = Role(
            name="auditor",
            description="Audit specialist",
            permissions=frozenset(
                {Permission.AUDIT_VIEW, Permission.AUDIT_EXPORT, Permission.AUDIT_VERIFY}
            ),
        )
        ac.add_role(custom)
        ac.add_user(_make_user(roles=frozenset({"auditor"})))
        assert ac.check("u1", Permission.AUDIT_EXPORT).allowed is True
        assert ac.check("u1", Permission.POLICY_EDIT).allowed is False

    def test_custom_role_overrides_builtin(self) -> None:
        """Adding a role with a built-in name replaces it."""
        ac = AccessController()
        limited_viewer = Role(
            name="viewer",
            description="Very limited viewer",
            permissions=frozenset({Permission.POLICY_VIEW}),
        )
        ac.add_role(limited_viewer)
        ac.add_user(_make_user(roles=frozenset({"viewer"})))
        assert ac.check("u1", Permission.AUDIT_VIEW).allowed is False


# ===================================================================
# Thread safety
# ===================================================================


class TestThreadSafety:
    def test_concurrent_check(self) -> None:
        """Concurrent permission checks must not raise or corrupt state."""
        ac = AccessController()
        for i in range(50):
            ac.add_user(
                _make_user(
                    user_id=f"u{i}",
                    roles=frozenset({"viewer"}),
                )
            )

        errors: list[Exception] = []

        def _check(uid: str) -> None:
            try:
                ac.check(uid, Permission.POLICY_VIEW)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(_check, f"u{i}") for i in range(50)]
            concurrent.futures.wait(futures)

        assert errors == []

    def test_concurrent_grant_and_check(self) -> None:
        """Grants and checks interleaved across threads stay consistent."""
        ac = AccessController()
        ac.add_user(_make_user(user_id="shared"))
        barrier = threading.Barrier(4)

        results: list[bool] = []

        def _grant_then_check() -> None:
            barrier.wait()
            ac.grant_role("shared", "editor")
            decision = ac.check("shared", Permission.POLICY_EDIT)
            results.append(decision.allowed)

        threads = [threading.Thread(target=_grant_then_check) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        # After all grants, the user must have editor
        assert ac.check("shared", Permission.POLICY_EDIT).allowed is True

    def test_concurrent_add_remove_users(self) -> None:
        """Adding and removing users concurrently must not corrupt state."""
        ac = AccessController()
        errors: list[Exception] = []

        def _add_remove(idx: int) -> None:
            uid = f"tmp_{idx}"
            try:
                ac.add_user(_make_user(user_id=uid, roles=frozenset({"viewer"})))
                ac.check(uid, Permission.POLICY_VIEW)
                ac.remove_user(uid)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(_add_remove, i) for i in range(40)]
            concurrent.futures.wait(futures)

        assert errors == []


# ===================================================================
# Permission enum completeness
# ===================================================================


class TestPermissionEnum:
    def test_all_values_unique(self) -> None:
        values = [p.value for p in Permission]
        assert len(values) == len(set(values))

    def test_expected_count(self) -> None:
        assert len(Permission) == 12
