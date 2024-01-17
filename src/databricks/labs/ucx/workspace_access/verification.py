import logging
from typing import Literal

from databricks.sdk import WorkspaceClient
from databricks.sdk.errors import PermissionDenied

from databricks.labs.ucx.config import WorkspaceConfig

# from databricks.labs.ucx.framework.crawlers import RuntimeBackend
from databricks.labs.ucx.framework.crawlers import StatementExecutionBackend
from databricks.labs.ucx.workspace_access.groups import MigrationState
from databricks.labs.ucx.workspace_access.manager import PermissionManager
from databricks.labs.ucx.workspace_access.secrets import SecretScopesSupport

logger = logging.getLogger(__name__)


class VerificationManager:
    def __init__(self, ws: WorkspaceClient, secrets_support: SecretScopesSupport, cfg: WorkspaceConfig):
        self._ws = ws
        self._secrets_support = secrets_support
        self._cfg = cfg
        self._sql_backend = StatementExecutionBackend(self._ws, self._cfg.warehouse_id)

    def verify(
        self, migration_state: MigrationState, target: Literal["backup", "account"], tuples: list[tuple[str, str]]
    ):
        for object_type, object_id in tuples:
            if object_type == "secrets":
                self.verify_applied_scope_acls(object_id, migration_state, target)
            else:
                self.verify_applied_permissions(object_type, object_id, migration_state, target)
        self.verify_roles_entitlements_members(migration_state, target)

    def verify_applied_permissions(
        self,
        object_type: str,
        object_id: str,
        migration_state: MigrationState,
        target: Literal["backup", "account"],
    ):
        logger.debug(f"Comparing permissions for {object_type}/{object_id}")
        base_attr = "temporary_name" if target == "backup" else "name_in_account"
        op = self._ws.permissions.get(object_type, object_id)
        for info in migration_state.groups:
            if not op.access_control_list:
                continue
            src_permissions = sorted(
                [
                    _
                    for _ in op.access_control_list
                    if _.group_name == info.name_in_workspace and _.group_name is not None
                ],
                key=lambda p: p.group_name,
            )
            dst_permissions = sorted(
                [
                    _
                    for _ in op.access_control_list
                    if _.group_name == getattr(info, base_attr) and _.group_name is not None
                ],
                key=lambda p: p.group_name,
            )
            logger.debug(f"Permissions on {object_type} object: {object_id} before migration: {src_permissions}")
            logger.debug(f"Permissions on {object_type} object: {object_id} after migration: {dst_permissions}")

            assert len(dst_permissions) == len(
                src_permissions
            ), f"Target permissions were not applied correctly for {object_type}/{object_id}"
            assert [t.all_permissions for t in dst_permissions] == [
                s.all_permissions for s in src_permissions
            ], f"Target permissions were not applied correctly for {object_type}/{object_id}"

    def verify_applied_scope_acls(
        self, scope_name: str, migration_state: MigrationState, target: Literal["backup", "account"]
    ):
        logger.debug(f"Comparing permissions for scope: {scope_name}")
        # base_attr = "name_in_workspace" if target == "backup" else "temporary_name"
        target_attr = "temporary_name" if target == "backup" else "name_in_account"
        for mi in migration_state.groups:
            src_name = mi.name_in_workspace
            dst_name = getattr(mi, target_attr)
            src_permission = self._secrets_support.secret_scope_permission(scope_name, src_name)
            dst_permission = self._secrets_support.secret_scope_permission(scope_name, dst_name)

            logger.debug(f"Permissions on secret scope: {scope_name} before migration: {src_permission}")
            logger.debug(f"Permissions on secret scope: {scope_name} after migration: {dst_permission}")

            assert src_permission == dst_permission, "Scope ACLs were not applied correctly"

    def verify_roles_entitlements_members(self, migration_state: MigrationState, target: Literal["backup", "account"]):
        target_attr = "external_id" if target == "backup" else "id_in_workspace"
        for el in migration_state.groups:
            comparison_base = getattr(el, "id_in_workspace" if target == "backup" else "id_in_workspace")
            comparison_target = getattr(el, target_attr)

            base_group_info = self._ws.groups.get(comparison_base)
            target_group_info = self._ws.groups.get(comparison_target)

            assert base_group_info.roles == target_group_info.roles
            assert base_group_info.entitlements == target_group_info.entitlements
            assert base_group_info.members == target_group_info.members

    def get_permissions_to_verify(self):
        # pm = PermissionManager.factory(
        #     self._ws,
        #     RuntimeBackend(),
        #     self._cfg.inventory_database,
        #     num_threads=self._cfg.num_threads,
        #     workspace_start_path=self._cfg.workspace_start_path,
        # )
        pm = PermissionManager(self._sql_backend, self._cfg.inventory_database, [])
        permissions = pm.load_all()

        return [(p.object_type, p.object_id) for p in permissions]

    def run(self, migration_state: MigrationState):
        permissions_to_verify = self.get_permissions_to_verify()
        # group_manager = GroupManager(
        #     self._sql_backend,
        #     self._ws,
        #     self._cfg.inventory_database,
        #     self._cfg.include_group_names,
        #     self._cfg.renamed_group_prefix,
        #     workspace_group_regex=self._cfg.workspace_group_regex,
        #     workspace_group_replace=self._cfg.workspace_group_replace,
        #     account_group_regex=self._cfg.account_group_regex,
        #     external_id_match=self._cfg.group_match_by_external_id,
        # )

        # migration_state = group_manager.get_migration_state()

        if len(migration_state.groups) == 0:
            logger.info("Skipping group migration as no groups were found.")
        else:
            self.verify(migration_state, "account", permissions_to_verify)


class VerifyHasMetastore:
    def __init__(self, ws: WorkspaceClient):
        self.metastore_id: str | None = None
        self.default_catalog_name: str | None = None
        self.workspace_id: int | None = None
        self._ws = ws

    def verify_metastore(self):
        """
        Verifies if a metastore exists for a metastore
        :param :
        :return:
        """

        try:
            current_metastore = self._ws.metastores.current()
            if current_metastore:
                self.default_catalog_name = current_metastore.default_catalog_name
                self.metastore_id = current_metastore.metastore_id
                self.workspace_id = current_metastore.workspace_id
                return True
            else:
                raise MetastoreNotFoundError
        except PermissionDenied:
            logger.error("Permission Denied while trying to access metastore")


class MetastoreNotFoundError(Exception):
    def __init__(self, message="Metastore not found in the workspace"):
        self.message = message
        super().__init__(self.message)
