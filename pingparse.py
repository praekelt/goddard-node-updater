import subprocess
import re


def network_quality_test(ip):
    print 'Running network test...'

    try:
        # ping -c5 -w60 -W5 -i2 - Ping 5 times, let ping run for 30 seconds, let each ping have 5 seconds to
        # pong, wait 2 seconds between each ping. These are very forgiving settings which seem to work better
        # over satellite.

        ping = subprocess.Popen(["ping", "-c5", "-w30", "-W5", "-i2", ip], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        out, error = ping.communicate()

        # 20 packets transmitted, 18 received, 10% packet loss, time 19031ms
        # rtt min/avg/max/mdev = 1487.500/1910.123/2439.946/359.608 ms, pipe 3

        stats = {'ip': ip}

        if out:
            try:
                for line in out.split('\n'):
                    if line.startswith('rtt min/avg/max/mdev = '):
                        stat_match = re.match('^.* = (.*)/(.*)/(.*)/(.*) ms,', line)
                        if stat_match:
                            s = stat_match.groups()
                            stats['min'] = s[0]
                            stats['avg'] = s[1]
                            stats['max'] = s[2]
                            stats['mdev'] = s[3]

                    if 'packet loss' in line:
                        packets_match = re.match('^(.*) packets transmitted, (.*) received, (.*) packet '
                                                 'loss, time (.*)$', line)
                        if packets_match:
                            p = packets_match.groups()
                            stats['packets_sent'] = p[0]
                            stats['packets_received'] = p[1]
                            stats['packet_loss'] = p[2]
                            stats['time'] = p[3]

                if stats:
                    return stats
                else:
                    print 'Could not parse response'
                return False

            except Exception, e:
                print 'Ping result parsing error:'
                print e

                return False
        else:
            print 'No Ping...'
            print error
            return False

    except subprocess.CalledProcessError:
        print 'Could not get a ping...'
        return False