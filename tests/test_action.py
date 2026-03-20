"""Tests for the Action model."""

from aegis.core.action import Action


def test_action_creation():
    action = Action(type="read", target="salesforce", params={"selector": ".list"})
    assert action.type == "read"
    assert action.target == "salesforce"
    assert action.params == {"selector": ".list"}
    assert action.description == ""


def test_action_with_description():
    action = Action(type="write", target="stripe", description="Update customer")
    assert action.description == "Update customer"


def test_action_is_frozen():
    action = Action(type="read", target="salesforce")
    try:
        action.type = "write"  # type: ignore[misc]
        assert False, "Should have raised"
    except AttributeError:
        pass


def test_action_str():
    action = Action(type="read", target="salesforce")
    assert "read" in str(action)
    assert "salesforce" in str(action)


def test_action_str_with_description():
    action = Action(type="write", target="stripe", description="Update customer")
    result = str(action)
    assert "write" in result
    assert "Update customer" in result


def test_action_default_params():
    action = Action(type="read", target="test")
    assert action.params == {}


def test_action_equality():
    a1 = Action(type="read", target="sf", params={"k": "v"})
    a2 = Action(type="read", target="sf", params={"k": "v"})
    assert a1 == a2


def test_action_not_hashable_with_dict_params():
    """Actions with dict params are not hashable (dict is mutable)."""
    a = Action(type="read", target="sf")
    try:
        hash(a)
        assert False, "Expected TypeError"
    except TypeError:
        pass
