from unittest.mock import Mock

import pytest

from databricks.labs.ucx.workspace_access.verification import VerificationManager


def test_verify(mocker):
    mock_migration_state = Mock()

    mock_verify_applied_scope_acls = mocker.patch(
        "databricks.labs.ucx.workspace_access.verification.VerificationManager.verify_applied_scope_acls"
    )
    mock_verify_applied_permissions = mocker.patch(
        "databricks.labs.ucx.workspace_access.verification.VerificationManager.verify_applied_permissions"
    )
    mock_verify_roles_entitlements_members = mocker.patch(
        "databricks.labs.ucx.workspace_access.verification.VerificationManager.verify_roles_entitlements_members"
    )

    tuples = [("secrets", "id1"), ("not_secrets", "id2")]

    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ss = Mock()
    ws_config = Mock()

    vm = VerificationManager(ws, ss, ws_config)
    vm.verify(mock_migration_state, "account", tuples)

    # Assert that the mocked methods were called with the correct arguments
    mock_verify_applied_scope_acls.assert_called_once_with("id1", mock_migration_state, "account")
    mock_verify_applied_permissions.assert_called_once_with("not_secrets", "id2", mock_migration_state, "account")
    mock_verify_roles_entitlements_members.assert_called_once_with(mock_migration_state, "account")


def test_get_permissions_to_verify(mocker):
    mock_pm = Mock()
    mock_permission = Mock()
    mock_permission.object_type = "object_type"
    mock_permission.object_id = "object_id"
    mock_pm.load_all.return_value = [mock_permission]
    mocker.patch("databricks.labs.ucx.workspace_access.verification.PermissionManager", return_value=mock_pm)

    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ss = Mock()
    ws_config = Mock(
        inventory_database="inventory_database",
        warehouse_id="warehouse_id",
    )

    vm = VerificationManager(ws, ss, ws_config)
    actual_permissions = vm.get_permissions_to_verify()

    assert actual_permissions == [("object_type", "object_id")]
    mock_pm.load_all.assert_called_once()


def test_run(mocker):
    mock_migration_state = mocker.Mock()
    mock_migration_state.groups = []

    mock_permissions_to_verify = [("object_type", "object_id")]
    mocker.patch(
        "databricks.labs.ucx.workspace_access.verification.VerificationManager.get_permissions_to_verify",
        return_value=mock_permissions_to_verify,
    )

    mock_verify = mocker.patch("databricks.labs.ucx.workspace_access.verification.VerificationManager.verify")

    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ss = Mock()
    ws_config = Mock()

    vm = VerificationManager(ws, ss, ws_config)

    vm.run(mock_migration_state)
    vm.get_permissions_to_verify.assert_called_once()
    mock_verify.assert_not_called()

    mock_migration_state.groups = ["group1", "group2"]
    vm.run(mock_migration_state)
    mock_verify.assert_called_once_with(mock_migration_state, "account", mock_permissions_to_verify)


def test_verify_roles_entitlements_members(mocker):
    # Create a mock MigrationState object
    mock_migration_state = Mock()
    mock_migration_state.groups = [
        Mock(
            id_in_workspace="id1",
            name_in_workspace="name1",
            name_in_account="name1",
            temporary_name="temp_name1",
            roles="roles1",
            entitlements="entitlements1",
            members="members1",
        )
    ]

    # Create mock group info objects
    mock_group_info = Mock()
    mock_group_info.display_name = "name1"
    mock_group_info.roles = "roles1"
    mock_group_info.entitlements = "entitlements1"
    mock_group_info.members = "members1"

    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ws.groups.get.return_value = mock_group_info
    ss = Mock()
    ws_config = Mock()

    vm = VerificationManager(ws, ss, ws_config)

    # assertions run in the method
    vm.verify_roles_entitlements_members(mock_migration_state, "account")


def test_verify_roles_entitlements_members_assertionerror(mocker):
    # Create a mock MigrationState object
    mock_migration_state = Mock()
    mock_migration_state.groups = [
        Mock(
            id_in_workspace="id1",
            name_in_workspace="name1",
            name_in_account="name1",
            temporary_name="temp_name1",
        )
    ]

    mock_group_info = Mock(
        display_name="name1",
        roles="roles1",
        entitlements="entitlements1",
        members="members1",
    )
    mock_group_info_2 = Mock(
        display_name="temp_name1",
        roles="roles2",
        entitlements="entitlements2",
        members="members2",
    )

    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ws.groups.get.side_effect = [mock_group_info, mock_group_info_2]
    ss = Mock()
    ws_config = Mock()

    vm = VerificationManager(ws, ss, ws_config)

    # assertions run in the method
    with pytest.raises(AssertionError):
        vm.verify_roles_entitlements_members(mock_migration_state, "account")


def test_verify_applied_scope_acls_succeed(mocker):
    mock_migration_state = Mock()
    mock_migration_state.groups = [Mock(name_in_workspace="name1", temporary_name="name2", name_in_account="name3")]

    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ss = Mock()
    mock_permission_1 = "permission"
    mock_permission_2 = "permission"
    ss.secret_scope_permission.side_effect = [mock_permission_1, mock_permission_2]
    ws_config = Mock()

    vm = VerificationManager(ws, ss, ws_config)

    # assertions run in the method
    vm.verify_applied_scope_acls("scope_name", mock_migration_state, "account")


def test_verify_applied_scope_acls_assertionerror(mocker):
    mock_migration_state = Mock()
    mock_migration_state.groups = [Mock(name_in_workspace="name1", temporary_name="name2", name_in_account="name3")]

    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ss = Mock()
    mock_permission_1 = "permission_1"
    mock_permission_2 = "permission_2"
    ss.secret_scope_permission.side_effect = [mock_permission_1, mock_permission_2]
    ws_config = Mock()

    vm = VerificationManager(ws, ss, ws_config)

    # assertions run in the method
    with pytest.raises(AssertionError):
        vm.verify_applied_scope_acls("scope_name", mock_migration_state, "account")


def test_verify_applied_permissions(mocker):
    mock_migration_state = Mock()
    mock_migration_state.groups = [Mock(name_in_workspace="name2", temporary_name="name2", name_in_account="name1")]

    mock_permission = Mock()
    mock_permission.group_name = "name1"
    mock_permission.all_permissions = "permissions1"

    mock_permission_2 = Mock()
    mock_permission_2.group_name = "name2"
    mock_permission_2.all_permissions = "permissions1"

    mock_op = Mock()
    mock_op.access_control_list = [mock_permission, mock_permission_2]

    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ws.permissions.get.return_value = mock_op
    ss = Mock()
    ws_config = Mock()

    vm = VerificationManager(ws, ss, ws_config)

    # assertions run in the method
    vm.verify_applied_permissions("pipelines", "123", mock_migration_state, "account")


def test_verify_applied_permissions_assertionerror(mocker):
    mock_migration_state = Mock()
    mock_migration_state.groups = [Mock(name_in_workspace="name2", temporary_name="name2", name_in_account="name1")]

    mock_permission = Mock()
    mock_permission.group_name = "name1"
    mock_permission.all_permissions = "permissions1"

    mock_permission_2 = Mock()
    mock_permission_2.group_name = "name2"
    mock_permission_2.all_permissions = "permissions2"

    mock_op = Mock()
    mock_op.access_control_list = [mock_permission, mock_permission_2]

    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ws.permissions.get.return_value = mock_op
    ss = Mock()
    ws_config = Mock()

    vm = VerificationManager(ws, ss, ws_config)

    # assertions run in the method
    with pytest.raises(AssertionError):
        vm.verify_applied_permissions("pipelines", "1234", mock_migration_state, "account")
