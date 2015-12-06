import spur
import sys
import os
import unirest
import json
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
import time
import smtplib
from email.mime.text import MIMEText
import signal
import subprocess

import pingparse
import utc
import uptimeparse

import settings

# TODO: Check that the node we're connecting to is the one that we think we are connecting to. (ie. check node.json)
# TODO: Check that we can pull content from data.goddard.com
# TODO: Possibly pull in some bgan data like temp, signal etc.
# TODO: Strip out and parse docker ps output
# TODO: Some smarter ps ax | grep rsync to try and spot hanging processes lots of dupes
# TODO: Pull down "free"
# TODO: Do not try and check nodes that are marked as disabled.
# TODO: Do a sanity check that all the of the tunnels that exist locally have been accounted for.
# TODO: Accept arguments for RUN_NETWORK_QUALITY_TEST etc.
# TODO: Option to change the RB750's `admin` password.
# TODO: Option to change the Grooves's `goddard` SSID password.
# TODO: Option to change the NUC's `goddard` password.

current_count = 0
nodes_up_count = 0
tunnel_broken_count = 0
report_start = None
report_data = []


class NodeCommsTimeoutError(Exception):
    pass


def main():
    global current_count, nodes_up_count, tunnel_broken_count, report_start

    if len(sys.argv) > 1:
        run_one(sys.argv[1])

    else:
        report_start = datetime.now()

        while True:
            current_count = 0
            nodes_up_count = 0
            tunnel_broken_count = 0

            run()

            print 'Sleeping for 15 minutes.'
            time.sleep(900)  # Sleep 15 minutes


def run_one(node_id):
    conn = psycopg2.connect(settings.PG_CONNECTION_STRING)
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute("SELECT * FROM nodes WHERE id = %s", (node_id,))
    node = cursor.fetchone()
    media_folder_size = du('/var/goddard/media/')
    run_updater(node, 1, cursor, media_folder_size)


def run():
    global report_start, report_data
    signal.signal(signal.SIGALRM, timeout_handler)

    post_to_slack(':rocket: Node Updater Starting Up...')

    conn = psycopg2.connect(settings.PG_CONNECTION_STRING)
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    media_folder_size = du('/var/goddard/media/')  # Please note that this is a string.

    cursor.execute("SELECT * FROM nodes order by id")
    node_list = cursor.fetchall()

    for node in node_list:
        print "%s" % datetime.now()

        # Set our timeout
        signal.alarm(settings.CHECK_NODE_TIMEOUT)  # 5 minutes to timeout

        r = None
        try:
            r = run_updater(node, len(node_list), cursor, media_folder_size)

        except NodeCommsTimeoutError:
            print 'Timeout on Node Comms'
            post_to_slack(":no_entry_sign: %s - Timeout while trying to communicate with Node." % linkit(node))

        except Exception, e:
            print 'Exception on Node Comms'
            post_to_slack(":feelsgood: %s - Exception while trying to communicate with Node.\n"
                          "Exception: %s" % (linkit(node), e))

        # Turn off our timeout.
        signal.alarm(0)

        if r:
            r['id'] = node['id']
            r['name'] = node['name']
            report_data.append(r)

        print ""

        if datetime.now() > report_start + timedelta(minutes=settings.REPORT_MINUTES):
            # Send the report
            send_report()
            report_data = []
            report_start = datetime.now()

    post_to_slack(":coffee: Node Updater Complete. %s of %s Nodes are online." % (nodes_up_count, len(node_list)))

    if tunnel_broken_count > 0:
        print "There are nodes with questionable connectivity."
        post_to_slack(":no_entry: There are %s nodes with questionable connectivity." % tunnel_broken_count)

    print "Update Run Complete"


def run_updater(node, node_count, cursor, media_folder_size):
    global current_count, nodes_up_count, tunnel_broken_count
    current_count += 1
    port = node['port']
    serial = node['serial']
    warnings = []
    errors = []
    notices = []
    statistics = []

    print '%s/%s: Trying Node #%s on Port %s' % (current_count, node_count, serial, port)

    # Get this Node's last IP
    cursor.execute("SELECT * FROM deviceinfos WHERE nodeid = %s ORDER BY \"createdAt\" DESC LIMIT 1", (node['id'], ))
    device_info = cursor.fetchone()

    # Start the real test.
    shell = spur.SshShell(
        hostname="localhost",
        port=port,
        username="root",
        connect_timeout=120,
        missing_host_key=spur.ssh.MissingHostKey.accept,
        private_key_file="/root/.ssh/id_rsa",
        shell_type=spur.ssh.ShellTypes.sh)

    with shell:

        # --------------------------------------------
        # Test our connection with an uptime.
        # --------------------------------------------
        try:
            result = shell.run(["uptime"])
            uptime = result.output.strip()
            try:
                uptime_object = uptimeparse.Uptime(uptime)

            except uptimeparse.ParsingError:
                print 'COULD NOT PARSE: %s' % uptime.output
                uptime_object = None

            nodes_up_count += 1
            print 'Node #%s appears to be up!' % serial

        except spur.ssh.ConnectionError:

            # We can't connect over the tunnel, so lets see if we can get to it via the external IP.

            if device_info:
                ip_date = device_info['createdAt']
                ip_age = datetime.now(utc.utc) - ip_date

                # We've received some data for this Node at some point in the past, lets try ping it.
                print "Pinging %s" % device_info['bgan_public_ip']
                response = os.system("ping -c1 -w%s %s > /dev/null 2>&1" % (settings.PING_TIMEOUT_CHECK_EXT,
                                                                            device_info['bgan_public_ip']))

                if response == 0:
                    print 'Node #%s responded to a ping! - We should investigate.' % serial
                    msg = ':no_entry: %s - Tunnel down but getting external ping response! ' % (linkit(node))
                    tunnel_broken_count += 1

                    print 'Node #%s killing hanging tunnel instance...' % serial,
                    os.system("kill $(lsof -i:" + str(port) + " -t)")
                    print 'Killed.'
                    post_to_slack(":hammer: %s - Restarting tunnel instance on Hub Server. Will try "
                                  "again on next loop." % linkit(node))

                else:
                    print 'Node #%s did not respond to a ping, it\'s probably down.' % serial
                    msg = ':warning: %s - Tunnel down and no external ping ' \
                          'response. ' % (linkit(node))

                msg += '    Last check-in was %s days and %s minutes ago.' % (ip_age.days, ip_age.seconds/60)
                post_to_slack(msg)

                # This tunnel/node is broken, exit this loop.
                return {'up': False, 'msg': None, 'warnings': warnings, 'errors': errors, 'notices': notices,
                        'statistics': statistics}

            else:
                print 'Node #%s has never received a check-in. Probably was never provisioned.' % serial
                post_to_slack(':grey_question: %s has never received a check-in. Probably never '
                              'provisioned.' % (linkit(node)))
                errors.append('This node has never been provisioned.')

                return {'up': False, 'msg': None, 'warnings': warnings, 'errors': errors, 'notices': notices,
                        'statistics': statistics}

        # We've got this far, so the Node's tunnel is up.

        try:
            msg_strs = [':green_heart: %s - ' % (linkit(node))]

            # --------------------------------------------
            # Rsync the Node Agent code
            # --------------------------------------------
            result = shell.run(["rsync", "-aPzri", "--exclude='.git/'", "--no-perms", "--no-owner", "--progress",
                                "node@hub.goddard.unicore.io:/var/goddard/agent/", "/var/goddard/agent"])

            if result.return_code == 0:
                print 'Node #%s rsync ran successfully' % serial

                # Did anything change?
                if len(result.output.split('\n')) > 2:

                    print 'Node #%s was updated with new changes for agent.' % serial
                    print 'Node #%s ensuring goddardboot service is present.' % serial

                    # Copy over the goddardboot script to upstart
                    shell.run(["cp", "/var/goddard/agent/scripts/boot.upstart.conf", "/etc/init/goddardboot.conf"])

                    # Restart the goddardboot service in case it changed
                    print 'Node #%s restarting the goddardboot service... ' % serial,
                    shell.run(["service", "goddardboot", "restart"])
                    print ' Restarted.'
                    msg_strs.append('Node Agent was updated.    GoddardBoot restarted.    ')

                else:
                    print 'Node #%s was already up to date.' % serial
                    msg_strs.append('Node Agent up to date.    ')

            else:
                print 'Node #' + str(port) + " something went wrong while trying to rsync"

            # --------------------------------------------
            # Update the crontab
            # --------------------------------------------
            result = shell.run(["sh", "/var/goddard/agent/scripts/set_cron.sh"])

            if result.return_code == 0:
                print 'Node #%s cron management ran successfully.' % serial
            else:
                print 'Node #%s cron management had a problem executing.' % serial

            # --------------------------------------------
            # Check how many rsync processes are running.
            # --------------------------------------------
            result = shell.run(["sh", "-c", "ps ax -o cmd | grep rsync"])

            lines = result.output.split("\n")
            rsync_count = 0

            for line in lines:
                if line.startswith('rsync'):
                    rsync_count += 1

            msg_strs.append('%s rsync processes running.    ' % rsync_count)
            print 'Node #%s has %s rsync processes running.' % (serial, rsync_count)

            # --------------------------------------------
            # Check if we can request mamawifi.com and get expected response.
            # --------------------------------------------
            result = shell.run(["sh", "-c", "curl --silent mamawifi.com"])

            if "swatch" in result.output:
                msg_strs.append('Nov 2015 Captive Portal is available.    ')
                print 'Node #%s Nov 2015 Captive Portal is available.' % serial

            else:
                if uptime_object.total_minutes() > 15:
                    msg_strs.append('Nov 2015 Captive Portal is NOT available. :feelsgood:    ')
                    print 'Node #%s Nov 2015 Captive Portal is NOT available.' % serial
                    warnings.append("Nov 2015 Captive Portal is NOT available.")

                else:
                    msg_strs.append("Nov 2015 Captive Portal is not available, but Node has just booted so we're "
                                    "ignoring that for now.    ")
                    print("Nov 2015 Captive Portal is not available, but Node has just booted so we're "
                          "ignoring that for now.    ")

            # --------------------------------------------
            # Conditionally kill old rsync processes
            # --------------------------------------------
            if settings.KILL_RSYNC_ON_CONNECT:
                print 'Node #' + str(port) + " - Killing rsync."
                result = shell.run(["killall", "rsync"])

                if result.return_code == 0:
                    print 'Node #%s had its rsync process killed' % serial
                else:
                    print 'Node #%s had no rsync processes to kill' % serial

            if settings.FETCH_NODE_JSON:
                # --------------------------------------------
                # Fetching Node Details
                # --------------------------------------------
                # This is a bit redundant now because we're running against the DB, but I want to leave it here.
                print 'Node #%s getting Node Details' % serial
                result = shell.run(["cat", "/var/goddard/node.json"])
                parsed_obj = json.loads(str(result.output))
                node_id_string = parsed_obj["name"] + ' #' + parsed_obj["serial"]
                print node_id_string

            # --------------------------------------------
            # Get the size of the media folder
            # --------------------------------------------
            print 'Node #%s checking media folder size: ' % serial,

            result = shell.run(["du", "-hs", "/var/goddard/media/"])

            if result.return_code == 0:
                node_media_size = result.output.split('\t')[0]
                if node_media_size != media_folder_size:
                    # The media folder sizes do not match

                    # Have we got 2 rsync processed running, or has the node only been up for < 1 hour ?
                    # Also, is this happening in a time that isn't between :58 and :7 minutes past the hour?

                    if rsync_count >= 2:
                        # Not up to date, but we are syncing...
                        msg_strs.append(":hourglass_flowing_sand: Media folder sizes do not match but we are "
                                        "currently syncing.    ")
                        print 'Media folder sizes do not match but we are currently syncing.'

                    else:
                        # Is this excusable ?
                        # 70 = 60 + 10 for boot.
                        if uptime_object.total_minutes() > 70 and 58 > datetime.now().minute > 7:

                            # Node syncing appears broken. We've been up for enough time to have started the sync,
                            # but we aren't syncing, and we aren't in a period where cron specifically kills
                            # the syncing.

                            warnings.append("Media sync appears broken. Folder sizes don't match, but Node has "
                                            "been up for %s minutes and has %s rsync processes running."
                                            % (uptime_object.total_minutes(), rsync_count))

                            msg_strs.append(":feelsgood: Media folder sizes do not match and we don't have > 2 "
                                            "rsync processes running.    ")

                            print 'Syncing appears broken...'

                        else:
                            # This is excusable...
                            msg_strs.append("Media folder sizes do not match and we aren't syncing, but we've either "
                                            "booted < 60 minutes ago or are in a time where we know cron might have "
                                            "stopped rsync.    ")
                            print("Media folder sizes do not match and rsync_count <2, but we're in a state where we "
                                  "can ignore.")

                else:
                    msg_strs.append(":white_check_mark: Media folder is synced successfully.    ")

                # add to the message that will be sent to Slack
                msg_strs.append('Media folder is %s/%s.    ' % (node_media_size, media_folder_size))

                print "%s." % node_media_size

            else:
                print 'Node #%s had problems getting the size.' % serial
                # add to the message that will be sent to Slack
                msg_strs.append(':feelsgood: Media folder size could not be determined.    ')

            # --------------------------------------------
            # Add in the uptime and load from earlier.
            # --------------------------------------------
            if uptime_object:
                print type(uptime_object)
                print uptime_object
                msg_strs.append('Uptime: %s days, %s hours, %s minutes.    '
                                % (uptime_object.days, uptime_object.hours, uptime_object.minutes))

                msg_strs.append('Load: %s, %s, %s.    ' %
                                (uptime_object.load1, uptime_object.load2, uptime_object.load3))

            else:
                msg_strs.append(':feelsgood: Uptime and Load were unable to be parsed.    ')

            # --------------------------------------------
            # Get the docker output
            # --------------------------------------------
            print 'Node #%s getting Docker output.' % serial
            # result = shell.run(["docker", "inspect", "--format='{{.Name}}'", "$(sudo docker ps -aq --no-trunc)"])
            result = shell.run(["docker", "ps"])

            msg_strs.append('\n```' + str(result.output) + '```\n')

            # --------------------------------------------
            # Send the results to Slack
            # --------------------------------------------
            msg = ''.join(msg_strs)
            post_to_slack(msg)

            return {'up': True, 'warnings': warnings, 'errors': errors, 'notices': notices, 'statistics': statistics,
                    'msg': msg}

        finally:

            if settings.RUN_NETWORK_QUALITY_TEST and device_info:
                network_quality_result = pingparse.network_quality_test(device_info['bgan_public_ip'])
            else:
                network_quality_result = None

            if network_quality_result:
                if network_quality_result['packet_loss'] != "100%":
                    post_to_slack("*Node #%s* Network Health: %s" % (serial, network_quality_result))


def post_to_slack(text):
    for hook in settings.SLACK_HOOKS:
        print 'Posting to %s Slack... ' % hook[0],
        response = unirest.post(
            hook[1],
            headers={"Accept": "application/json"},
            params=json.dumps({
                'text': text
            }))
        print "%s." % response.body.strip()


def send_report():
    global report_data
    print "Generating Report"
    post_to_slack(":email: Generating Node Report for Email...")
    reporting_period = datetime.now() - report_start
    out = "Goddard Node Report\n"
    out += "Reporting Period: %s hours\n" % ((reporting_period.days * 24) + (reporting_period.seconds / 3600))
    out += "Reports: %s (includes checking Nodes that have never been up)" % len(report_data)

    # Generate two lists of all the nodes, which ends up with the most recent up report we have for the each node.
    up_nodes = {}
    down_nodes = {}

    for r in report_data:
        if r['up']:
            # Add node to up list, remove from down list. Cognisant that we're overwriting Node's so that
            # we only show the most recent report.
            up_nodes[r['id']] = r
            down_nodes.pop(r['id'], None)

        else:
            # Add down nodes to the down list, but only if they're not in the up list already.
            if r['id'] not in up_nodes.keys():
                down_nodes[r['id']] = r

    out += "\nNodes UP: %s (during the reporting period)\n\n" % len(up_nodes)
    out += "Details:\n"

    for k, v in up_nodes.items():
        out += "%s\n" % v['msg']

    print "================== NODE REPORT ====================="
    print out
    print "===================================================="

    msg = MIMEText(out)
    msg['Subject'] = 'Goddard Node Updater Report Email'
    msg['From'] = 'nodeupdater@hub.goddard.unicore.io'
    msg['To'] = 'arbitraryuser@gmail.com'

    s = smtplib.SMTP('localhost')
    s.sendmail('nodeupdater@hub.goddard.unicore.io', settings.REPORT_EMAILS, msg.as_string())
    s.quit()
    post_to_slack(":email: Report Sent. ")
    print "Report Sent"


def linkit(node):
    return '''Node <http://hub.goddard.unicore.io/nodes/%s|#%s> on Port %s''' % (node['id'], node['serial'],
                                                                                 node['port'])


def du(path):
    p = subprocess.Popen(["du", "-cksh", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, error = p.communicate()
    # The last line of output, split on tabs, the first entry, stripped for good measure.
    size = out.strip().split('\n')[-1].split('\t')[0].strip()
    return size


def timeout_handler(signum, frame):
    print "Timeout! %s %s" % (signum, frame)
    raise NodeCommsTimeoutError


# Start this party
main()
