from unittest.mock import Mock, patch
import os, sys
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
    mock_verify_schema_permissions = mocker.patch(
        "databricks.labs.ucx.workspace_access.verification.VerificationManager.verify_schema_permissions"
    )
    mock_verify_table_permissions = mocker.patch(
        "databricks.labs.ucx.workspace_access.verification.VerificationManager.verify_table_permissions"
    )

    tuples = [("secrets", "id1"), ("not_secrets", "id2")]

    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ss = Mock()
    ws_config = Mock()

    with patch.dict(os.environ, {"DATABRICKS_RUNTIME_VERSION": "14.0"}):
        pyspark_sql_session = Mock()
        sys.modules["pyspark.sql.session"] = pyspark_sql_session
        vm = VerificationManager(ws, ss, ws_config)
    # vm = VerificationManager(ws, ss, ws_config)
    vm.verify(mock_migration_state, "account", tuples)

    # Assert that the mocked methods were called with the correct arguments
    mock_verify_applied_scope_acls.assert_called_once_with("id1", mock_migration_state, "account")
    mock_verify_applied_permissions.assert_called_once_with("not_secrets", "id2", mock_migration_state, "account")
    mock_verify_roles_entitlements_members.assert_called_once_with(mock_migration_state, "account")
    mock_verify_schema_permissions.assert_called_once()
    mock_verify_table_permissions.assert_called_once()


def test_get_permissions_to_verify(mocker):
    mock_pm = Mock()
    mock_permission = Mock(
        object_type="object_type",
        object_id="object_id",
        raw="raw",
    )
    mock_pm.load_all.return_value = [mock_permission]
    mocker.patch("databricks.labs.ucx.workspace_access.verification.PermissionManager", return_value=mock_pm)

    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ss = Mock()
    ws_config = Mock(
        inventory_database="inventory_database",
        warehouse_id="warehouse_id",
    )

    with patch.dict(os.environ, {"DATABRICKS_RUNTIME_VERSION": "14.0"}):
        pyspark_sql_session = Mock()
        sys.modules["pyspark.sql.session"] = pyspark_sql_session
        vm = VerificationManager(ws, ss, ws_config)

    actual_permissions = vm.get_all_permissions()

    assert actual_permissions == [mock_permission]
    mock_pm.load_all.assert_called_once()


def test_run(mocker):
    mock_migration_state = mocker.Mock()
    mock_migration_state.groups = []

    mock_permission = Mock(
        object_type="object_type",
        object_id="object_id",
        raw="raw",
    )
    mock_permissions_to_verify = [mock_permission]
    mocker.patch(
        "databricks.labs.ucx.workspace_access.verification.VerificationManager.get_all_permissions",
        return_value=mock_permissions_to_verify,
    )

    mock_verify = mocker.patch("databricks.labs.ucx.workspace_access.verification.VerificationManager.verify")

    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ss = Mock()
    ws_config = Mock()

    with patch.dict(os.environ, {"DATABRICKS_RUNTIME_VERSION": "14.0"}):
        pyspark_sql_session = Mock()
        sys.modules["pyspark.sql.session"] = pyspark_sql_session
        vm = VerificationManager(ws, ss, ws_config)

    vm.run(mock_migration_state)
    vm.get_all_permissions.assert_called_once()
    mock_verify.assert_not_called()

    mock_migration_state.groups = ["group1", "group2"]
    vm.run(mock_migration_state)
    mock_verify.assert_called_once_with(mock_migration_state, "account", [("object_type", "object_id")])


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

    with patch.dict(os.environ, {"DATABRICKS_RUNTIME_VERSION": "14.0"}):
        pyspark_sql_session = Mock()
        sys.modules["pyspark.sql.session"] = pyspark_sql_session
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

    with patch.dict(os.environ, {"DATABRICKS_RUNTIME_VERSION": "14.0"}):
        pyspark_sql_session = Mock()
        sys.modules["pyspark.sql.session"] = pyspark_sql_session
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

    with patch.dict(os.environ, {"DATABRICKS_RUNTIME_VERSION": "14.0"}):
        pyspark_sql_session = Mock()
        sys.modules["pyspark.sql.session"] = pyspark_sql_session
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

    with patch.dict(os.environ, {"DATABRICKS_RUNTIME_VERSION": "14.0"}):
        pyspark_sql_session = Mock()
        sys.modules["pyspark.sql.session"] = pyspark_sql_session
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

    with patch.dict(os.environ, {"DATABRICKS_RUNTIME_VERSION": "14.0"}):
        pyspark_sql_session = Mock()
        sys.modules["pyspark.sql.session"] = pyspark_sql_session
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

    with patch.dict(os.environ, {"DATABRICKS_RUNTIME_VERSION": "14.0"}):
        pyspark_sql_session = Mock()
        sys.modules["pyspark.sql.session"] = pyspark_sql_session
        vm = VerificationManager(ws, ss, ws_config)

    # assertions run in the method
    with pytest.raises(AssertionError):
        vm.verify_applied_permissions("pipelines", "1234", mock_migration_state, "account")


def test_verify_schema_permissions(mocker):
    mock_permissions = [
        Mock(object_type='DATABASE', object_id='schema1', raw='{"principal": "user1", "action_type": "SELECT"}')
    ]
    mocker.patch(
        'databricks.labs.ucx.workspace_access.verification.VerificationManager.get_all_permissions',
        return_value=mock_permissions,
    )

    mocker.patch(
        'databricks.labs.ucx.workspace_access.verification.VerificationManager._get_schema_list',
        return_value=['schema1'],
    )

    mock_df = Mock()
    mock_row = Mock(Principal='user1', ActionType='SELECT')
    mock_df.collect.return_value = [mock_row]
    pyspark_sql_session = Mock()
    sys.modules["pyspark.sql.session"] = pyspark_sql_session
    pyspark_sql_session.SparkSession.builder.getOrCreate.return_value.sql.return_value = mock_df
    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ss = Mock()
    ws_config = Mock()

    with patch.dict(os.environ, {"DATABRICKS_RUNTIME_VERSION": "14.0"}):
        vm = VerificationManager(ws, ss, ws_config)

    # this one contains the assertions
    vm.verify_schema_permissions()

    vm.get_all_permissions.assert_called_once()
    vm._get_schema_list.assert_called_once()
    vm._spark.sql.assert_called_once_with('SHOW GRANTS ON SCHEMA schema1')
    mock_df.collect.assert_called_once()


def test_verify_schema_permissions_fail(mocker):
    mock_permissions = [
        Mock(object_type='DATABASE', object_id='schema1', raw='{"principal": "user1", "action_type": "USAGE"}'),
    ]
    mocker.patch(
        'databricks.labs.ucx.workspace_access.verification.VerificationManager.get_all_permissions',
        return_value=mock_permissions,
    )

    mocker.patch(
        'databricks.labs.ucx.workspace_access.verification.VerificationManager._get_schema_list',
        return_value=['schema1'],
    )

    mock_df = Mock()
    mock_row = Mock(Principal='user1', ActionType='SELECT')
    mock_df.collect.return_value = [mock_row]
    pyspark_sql_session = Mock()
    sys.modules["pyspark.sql.session"] = pyspark_sql_session
    pyspark_sql_session.SparkSession.builder.getOrCreate.return_value.sql.return_value = mock_df

    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ss = Mock()
    ws_config = Mock()

    with patch.dict(os.environ, {"DATABRICKS_RUNTIME_VERSION": "14.0"}):
        vm = VerificationManager(ws, ss, ws_config)

    # this one contains the assertions
    with pytest.raises(AssertionError):
        vm.verify_schema_permissions()

    vm.get_all_permissions.assert_called_once()
    vm._get_schema_list.assert_called_once()
    vm._spark.sql.assert_called_once_with('SHOW GRANTS ON SCHEMA schema1')
    mock_df.collect.assert_called_once()


def test_verify_table_permissions(mocker):
    table_name = 'hive_metastore.schema_name.table_name'
    mock_permissions = [
        Mock(
            object_type='TABLE',
            object_id=table_name,
            raw='{"principal": "user1", "action_type": "SELECT, MODIFY"}',
        )
    ]
    mocker.patch(
        'databricks.labs.ucx.workspace_access.verification.VerificationManager.get_all_permissions',
        return_value=mock_permissions,
    )

    mocker.patch(
        'databricks.labs.ucx.workspace_access.verification.VerificationManager._get_table_list',
        return_value=[table_name],
    )

    mock_df = Mock()
    mock_row_1 = Mock(Principal='user1', ActionType='SELECT')
    mock_row_2 = Mock(Principal='user1', ActionType='MODIFY')
    mock_df.collect.return_value = [mock_row_1, mock_row_2]
    pyspark_sql_session = Mock()
    sys.modules["pyspark.sql.session"] = pyspark_sql_session
    pyspark_sql_session.SparkSession.builder.getOrCreate.return_value.sql.return_value = mock_df
    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ss = Mock()
    ws_config = Mock()

    with patch.dict(os.environ, {"DATABRICKS_RUNTIME_VERSION": "14.0"}):
        vm = VerificationManager(ws, ss, ws_config)

    # this one contains the assertions
    vm.verify_table_permissions()

    vm.get_all_permissions.assert_called_once()
    vm._get_table_list.assert_called_once()
    vm._spark.sql.assert_called_once_with(f'SHOW GRANTS ON {table_name}')
    mock_df.collect.assert_called_once()


def test_verify_table_permissions_fail(mocker):
    table_name = 'hive_metastore.schema_name.table_name'
    mock_permissions = [
        Mock(
            object_type='TABLE',
            object_id=table_name,
            raw='{"principal": "user1", "action_type": "SELECT, MODIFY, READ_METADATA"}',
        )
    ]
    mocker.patch(
        'databricks.labs.ucx.workspace_access.verification.VerificationManager.get_all_permissions',
        return_value=mock_permissions,
    )

    mocker.patch(
        'databricks.labs.ucx.workspace_access.verification.VerificationManager._get_table_list',
        return_value=[table_name],
    )

    mock_df = Mock()
    mock_row_1 = Mock(Principal='user1', ActionType='SELECT')
    mock_row_2 = Mock(Principal='user1', ActionType='MODIFY')
    mock_df.collect.return_value = [mock_row_1, mock_row_2]
    pyspark_sql_session = Mock()
    sys.modules["pyspark.sql.session"] = pyspark_sql_session
    pyspark_sql_session.SparkSession.builder.getOrCreate.return_value.sql.return_value = mock_df
    ws = mocker.patch("databricks.sdk.WorkspaceClient.__init__")
    ss = Mock()
    ws_config = Mock()

    with patch.dict(os.environ, {"DATABRICKS_RUNTIME_VERSION": "14.0"}):
        vm = VerificationManager(ws, ss, ws_config)

    # this one contains the assertions
    with pytest.raises(AssertionError):
        vm.verify_table_permissions()

    vm.get_all_permissions.assert_called_once()
    vm._get_table_list.assert_called_once()
    vm._spark.sql.assert_called_once_with(f'SHOW GRANTS ON {table_name}')
    mock_df.collect.assert_called_once()
