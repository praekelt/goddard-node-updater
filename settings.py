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


try:
    from local_settings import *
except ImportError:
    pass