import json
import logging
import typing
from functools import partial

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.iam import Group
from ratelimit import limits, sleep_and_retry

from databricks.labs.ucx.config import GroupsConfig
from databricks.labs.ucx.generic import StrEnum
from databricks.labs.ucx.providers.groups_info import (
    GroupMigrationState,
    MigrationGroupInfo,
)
from databricks.labs.ucx.utils import ThreadedExecution

logger = logging.getLogger(__name__)


class GroupLevel(StrEnum):
    WORKSPACE = "workspace"
    ACCOUNT = "account"


class GroupManager:
    SYSTEM_GROUPS: typing.ClassVar[list[str]] = ["users", "admins", "account users"]

    def __init__(self, ws: WorkspaceClient, groups: GroupsConfig):
        self._ws = ws
        self.config = groups
        self._migration_state: GroupMigrationState = GroupMigrationState()

    # please keep the internal methods below this line

    def _find_eligible_groups(self) -> list[str]:
        logger.info("Finding eligible groups automatically")
        _display_name_filter = " and ".join([f'displayName ne "{group}"' for group in GroupManager.SYSTEM_GROUPS])
        ws_groups = list(self._ws.groups.list(attributes="displayName,meta", filter=_display_name_filter))
        eligible_groups = [g for g in ws_groups if g.meta.resource_type == "WorkspaceGroup"]
        logger.info(f"Found {len(eligible_groups)} eligible groups")
        return [g.display_name for g in eligible_groups]

    @sleep_and_retry
    @limits(calls=100, period=1)  # assumption
    def _list_account_level_groups(
        self, filter: str, attributes: str | None = None, excluded_attributes: str | None = None  # noqa: A002
    ) -> list[Group]:
        query = {"filter": filter, "attributes": attributes, "excludedAttributes": excluded_attributes}
        response = self._ws.api_client.do("GET", "/api/2.0/account/scim/v2/Groups", query=query)
        return [Group.from_dict(v) for v in response.get("Resources", [])]

    def _get_group(self, group_name, level: GroupLevel) -> Group | None:
        # TODO: calling this can cause issues for SCIM backend, cache groups instead
        method = self._ws.groups.list if level == GroupLevel.WORKSPACE else self._list_account_level_groups
        query_filter = f"displayName eq '{group_name}'"
        attributes = ",".join(["id", "displayName", "meta", "entitlements", "roles", "members"])

        group = next(
            iter(method(filter=query_filter, attributes=attributes)),
            None,
        )

        return group

    def _get_or_create_backup_group(self, source_group_name: str, source_group: Group) -> Group:
        backup_group_name = f"{self.config.backup_group_prefix}{source_group_name}"
        backup_group = self._get_group(backup_group_name, GroupLevel.WORKSPACE)

        if backup_group:
            logger.info(f"Backup group {backup_group_name} already exists, no action required")
        else:
            logger.info(f"Creating backup group {backup_group_name}")
            backup_group = self._ws.groups.create(
                display_name=backup_group_name,
                meta=source_group.meta,
                entitlements=source_group.entitlements,
                roles=source_group.roles,
                members=source_group.members,
            )
            logger.info(f"Backup group {backup_group_name} successfully created")

        return backup_group

    def _set_migration_groups(self, groups_names: list[str]):
        def get_group_info(name: str):
            ws_group = self._get_group(name, GroupLevel.WORKSPACE)
            assert ws_group, f"Group {name} not found on the workspace level"
            acc_group = self._get_group(name, GroupLevel.ACCOUNT)
            assert acc_group, f"Group {name} not found on the account level"
            backup_group = self._get_or_create_backup_group(source_group_name=name, source_group=ws_group)
            return MigrationGroupInfo(workspace=ws_group, backup=backup_group, account=acc_group)

        executables = [partial(get_group_info, group_name) for group_name in groups_names]

        collected_groups = ThreadedExecution[MigrationGroupInfo](executables).run()
        for g in collected_groups:
            self._migration_state.add(g)

        logger.info(f"Prepared {len(collected_groups)} groups for migration")

    def _replace_group(self, migration_info: MigrationGroupInfo):
        ws_group = migration_info.workspace
        acc_group = migration_info.account

        if self._get_group(ws_group.display_name, GroupLevel.WORKSPACE):
            logger.info(f"Deleting the workspace-level group {ws_group.display_name} with id {ws_group.id}")
            self._ws.groups.delete(ws_group.id)
            logger.info(f"Workspace-level group {ws_group.display_name} with id {ws_group.id} was deleted")
        else:
            logger.warning(f"Workspace-level group {ws_group.display_name} does not exist, skipping")

        self._reflect_account_group_to_workspace(acc_group)

    @sleep_and_retry
    @limits(calls=5, period=1)  # assumption
    def _reflect_account_group_to_workspace(self, acc_group: Group) -> None:
        logger.info(f"Reflecting group {acc_group.display_name} to workspace")

        # TODO: add OpenAPI spec for it
        principal_id = acc_group.id
        permissions = ["USER"]
        path = f"/api/2.0/preview/permissionassignments/principals/{principal_id}"
        self._ws.api_client.do("PUT", path, data=json.dumps({"permissions": permissions}))

        logger.info(f"Group {acc_group.display_name} successfully reflected to workspace")

    # please keep the public methods below this line

    def prepare_groups_in_environment(self):
        logger.info("Preparing groups in the current environment")
        logger.info("At this step we'll verify that all groups exist and are of the correct type")
        logger.info("If some temporary groups are missing, they'll be created")
        if self.config.selected:
            logger.info("Using the provided group listing")

            for g in self.config.selected:
                assert g not in self.SYSTEM_GROUPS, f"Cannot migrate system group {g}"

            self._set_migration_groups(self.config.selected)
        else:
            logger.info("No group listing provided, finding eligible groups automatically")
            self._set_migration_groups(groups_names=self._find_eligible_groups())
        logger.info("Environment prepared successfully")

    @property
    def migration_groups_provider(self) -> GroupMigrationState:
        assert len(self._migration_state.groups) > 0, "Migration groups were not loaded or initialized"
        return self._migration_state

    def replace_workspace_groups_with_account_groups(self):
        logger.info("Replacing the workspace groups with account-level groups")
        logger.info(f"In total, {len(self.migration_groups_provider.groups)} group(s) to be replaced")

        executables = [
            partial(self._replace_group, migration_info) for migration_info in self.migration_groups_provider.groups
        ]
        ThreadedExecution(executables).run()
        logger.info("Workspace groups were successfully replaced with account-level groups")

    def delete_backup_groups(self):
        logger.info("Deleting the workspace-level backup groups")
        logger.info(f"In total, {len(self.migration_groups_provider.groups)} group(s) to be deleted")

        for migration_info in self.migration_groups_provider.groups:
            try:
                self._ws.groups.delete(id=migration_info.backup.id)
            except Exception as e:
                logger.warning(
                    f"Failed to delete backup group {migration_info.backup.display_name} "
                    f"with id {migration_info.backup.id}"
                )
                logger.warning(f"Original exception {e}")

        logger.info("Backup groups were successfully deleted")