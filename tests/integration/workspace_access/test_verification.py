import json
import logging

from databricks.sdk.service.iam import PermissionLevel
from databricks.sdk.service.workspace import AclPermission

from databricks.labs.ucx.config import WorkspaceConfig
from databricks.labs.ucx.workspace_access.base import Permissions
from databricks.labs.ucx.workspace_access.groups import MigrationState
from databricks.labs.ucx.workspace_access.manager import PermissionManager
from databricks.labs.ucx.workspace_access.secrets import SecretScopesSupport
from databricks.labs.ucx.workspace_access.verification import VerificationManager

logger = logging.getLogger(__name__)


def test_verification(
    ws,
    sql_backend,
    make_schema,
    make_random,
    make_group,
    make_group_pair,
    make_ucx_group,
    make_user,
    make_secret_scope,
    make_secret_scope_acl,
    make_pipeline,
    make_pipeline_permissions,
):
    migrated_group = make_group_pair()
    migration_state = MigrationState([migrated_group])

    scope = make_secret_scope()
    make_secret_scope_acl(scope=scope, principal=migrated_group.name_in_workspace, permission=AclPermission.WRITE)

    pipeline = make_pipeline()
    make_pipeline_permissions(
        object_id=pipeline.pipeline_id,
        permission_level=PermissionLevel.CAN_MANAGE,
        group_name=migrated_group.name_in_workspace,
    )

    backup_group_prefix = "old_"
    inventory_database = "ucx_inventory_verification"
    make_schema(catalog_name="hive_metastore", name=inventory_database)

    scope_acl_items = ws.secrets.list_acls(scope)
    scope_acl_raw = json.dumps([item.as_dict() for item in scope_acl_items])

    pipeline_acl_items = ws.permissions.get("pipelines", pipeline.pipeline_id)
    pipeline_acl_raw = json.dumps(pipeline_acl_items.as_dict())

    saved = [
        Permissions(object_id=scope, object_type="secrets", raw=scope_acl_raw),
        Permissions(object_id=pipeline.pipeline_id, object_type="pipelines", raw=pipeline_acl_raw),
    ]

    permission_manager = PermissionManager(sql_backend, inventory_database, [])
    permission_manager._save(saved)
    # # loaded = pi.load_all()

    make_secret_scope_acl(scope=scope, principal=migrated_group.name_in_account, permission=AclPermission.WRITE)

    make_pipeline_permissions(
        object_id=pipeline.pipeline_id,
        permission_level=PermissionLevel.CAN_MANAGE,
        group_name=migrated_group.name_in_account,
    )

    ws_config = WorkspaceConfig(
        inventory_database=inventory_database,
        include_group_names=[migrated_group.name_in_workspace],
        renamed_group_prefix=backup_group_prefix,
        warehouse_id=sql_backend._warehouse_id,
        log_level="DEBUG",
    )

    verification_manager = VerificationManager(ws, SecretScopesSupport(ws), ws_config)
    verification_manager.run(migration_state)
