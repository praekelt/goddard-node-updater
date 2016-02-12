KILL_RSYNC_ON_CONNECT = False
FETCH_NODE_JSON = False

PING_TIMEOUT_CHECK_EXT = 10   # Seconds to wait for a response from the Node via the external IP
CHECK_NODE_TIMEOUT = 300  # How many seconds should we wait for an individual node check to complete

RUN_NETWORK_QUALITY_TEST = True
PG_CONNECTION_STRING = "host='localhost' dbname='thedbname' user='postgres'"

NODE_UPDATER_DB_NAME = "theotherdbname"
NODE_UPDATER_DB_USER_NAME = "postgres"

REPORT_EMAILS = ["foo@bar.com", "ding@bat.com"]
REPORT_MINUTES = 1440

SLACK_HOOKS = [('team1_name', 'https://hooks.slack.com/services/xxxxxxx/yyyyyyyyy',),
               ('team2_name', 'https://hooks.slack.com/services/wwwwwww/zzzzzzzzz',)]


EXECUTE_MIKROTIK_UPDATE_1 = False
RB750_PASSWORD = "OldPassword1"
GROOVE_PASSWORD = "OldPassword2"
NEW_RB750_PASSWORD = "SuperSecurePassword1"
NEW_GROOVE_PASSWORD = "SuperSecurePassword2"
NEW_GROOVE_WLAN_PASSWORD = "SuperSecurePassword3"

CHANGE_GODDARD_PASSWORD = False
NEW_GODDARD_USER_PASSWORD = "SuperSecurePassword4"

EXECUTE_MIKROTIK_UPDATE_2 = False   # MTU CHANGE ON THE RB750
EXECUTE_MIKROTIK_UPDATE_3 = False   # Set the groove's `goddard` password
try:
    from local_settings import *
except ImportError:
    pass
