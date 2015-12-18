from peewee import *
import settings

db = PostgresqlDatabase(settings.NODE_UPDATER_DB_NAME, user=settings.NODE_UPDATER_DB_USER_NAME, host="localhost")


class Result(Model):
    date_in = DateTimeField(index=True)
    node_id = IntegerField(index=True)
    is_up = BooleanField(default=False, index=True)
    last_check_in = DateTimeField(null=True)
    uptime_minutes = IntegerField(null=True)
    packet_loss = FloatField(null=True)
    tunnel_up = BooleanField(null=True)
    external_ping_up = BooleanField(null=True)
    node_agent_rsync_success = BooleanField(null=True)
    node_agent_updated = BooleanField(null=True)
    restarted_goddardboot = BooleanField(null=True)
    cron_set_success = BooleanField(null=True)
    rsync_process_count = IntegerField(null=True)
    captive_portal_available = BooleanField(null=True)
    captive_portal_available_error = BooleanField(null=True)
    data_goddard_com_available = BooleanField(null=True)
    killed_rsync_processes = BooleanField(null=True)
    fetched_node_json = BooleanField(null=True)
    media_folder_size = CharField(null=True, max_length=25)
    media_sync_complete = BooleanField(null=True)
    media_sync_error = BooleanField(null=True)
    docker_ps_output = CharField(null=True, max_length=1000)
    docker_container_good_state = BooleanField(null=True)
    load1 = DecimalField(null=True)
    load2 = DecimalField(null=True)
    load3 = DecimalField(null=True)
    memory_used_percent = DecimalField(null=True)
    never_provisioned = BooleanField(null=True)

    class Meta:
        database = db
        db_table = 'nu_result'

class NodeSiteMeta(Model):
    node_id = IntegerField(index=True)
    ip_address = CharField(null=True, max_length=40)
    site_name = CharField(null=True, max_length=255)

    class Meta
        database = db
        db_table = 'nu_node_site_meta'

class MigrationHistory(Model):
    node_id = IntegerField(index=True)
    migration_slug = CharField(max_length=64)
    date_in = DateTimeField(index=True)
    success = BooleanField(default=False)

    class Meta:
        database = db
        db_table = 'nu_migration_history'


def connect():
    db.connect()


def create_tables():

    if not Result.table_exists():
        print "Created nu_result table."
        db.create_tables([Result])

    if not Result.table_exists():
        print "Created nu_node_site_meta table."
        db.create_tables([NodeSiteMeta])

    if not MigrationHistory.table_exists():
        print "Created nu_migration_history table."
        db.create_tables([MigrationHistory])
