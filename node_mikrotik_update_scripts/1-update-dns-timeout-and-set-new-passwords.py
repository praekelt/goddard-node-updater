import socket
import argparse

import mikrotik_api

parser = argparse.ArgumentParser(description='Modify the Mikrotik devices.')

parser.add_argument('--rb750_password', help="The current admin password for the RB750.")
parser.add_argument('--groove_password', help="The current admin password for the Groove.")

parser.add_argument('--new_rb750_password', help="The new admin password for the RB750.")
parser.add_argument('--new_groove_password', help="The new admin password for the Groove.")
parser.add_argument('--new_groove_wlan_password', help="The new password for the hidden `goddard` SSID.")

args = parser.parse_args()

if (not args.rb750_password or not args.groove_password or not args.new_rb750_password or
        not args.new_groove_password or not args.new_groove_wlan_password):

    parser.error("All arguments need to be provided... Run -h if unsure.")


# What we know
RB750_USER = 'admin'
RB750_IP = '192.168.0.5'
RB750_PASSWORD = args.rb750_password


GROOVE_USER = 'admin'
GROOVE_IP = '192.168.0.10'
GROOVE_PASSWORD = args.groove_password

PORT = 8728

# The name of the security profile attached to the "goddard" hidden SSID.
GODDARD_SECURITY_PROFILE_NAME = 'default'  # "goddard" in production
MIN_PASSWORD_LENGTH = 6

# What we are going to set
NEW_RB750_PASSWORD = args.new_rb750_password
NEW_GROOVE_PASSWORD = args.new_groove_password
NEW_GROOVE_WLAN_PASSWORD = args.new_groove_wlan_password


# Check that we have sane values
#if NEW_RB750_PASSWORD == NEW_GROOVE_PASSWORD or NEW_GROOVE_PASSWORD == NEW_GROOVE_WLAN_PASSWORD or \
#   NEW_GROOVE_WLAN_PASSWORD == NEW_RB750_PASSWORD:
#    raise Exception("New passwords need to be unique.")

# Check that all the passwords are long enough
if (len(NEW_RB750_PASSWORD) < MIN_PASSWORD_LENGTH or len(NEW_GROOVE_PASSWORD) < MIN_PASSWORD_LENGTH or
    len(NEW_GROOVE_WLAN_PASSWORD) < MIN_PASSWORD_LENGTH):
    raise Exception('New passwords need to be at least %s characters long.' % MIN_PASSWORD_LENGTH)


print '========================\n     PHASE 1 - RB750\n========================'

# Set up the socket, connect, login...
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RB750_IP, PORT))
x = mikrotik_api.MikrotikAPI(s)
x.login(RB750_USER, RB750_PASSWORD)

print '1. GETTING CURRENT DNS SETTINGS.'
original_dns = x.converse(['/ip/dns/print'])

print '2. SETTING DNS SERVER TIMEOUT.'
set_new_timeout_res = x.converse(['/ip/dns/set', '=query-server-timeout=10'])

print '3. GETTING NEW DNS SETTINGS.'
new_dns = x.converse(['/ip/dns/print'])

print '4. IDENTIFYING ADMIN USER.'
users = x.converse(['/user/print'])
admin = None
for user in users:
    if u'=name=admin' in user:
        admin = user
        break

if not admin:
    raise Exception('Can not locate RB750\'s ROS admin user.')

print '5. ADMIN USER IS:'
print admin

print '6. CHANGING ADMIN PASSWORD.'
password_set1 = x.converse(['/user/set', admin[1], '=password=%s' % NEW_RB750_PASSWORD])

print ""
print ""
print '========================\n  PHASE 2 - GROOVE WIFI\n========================'

# Set up the socket, connect, login...
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((GROOVE_IP, PORT))
x = mikrotik_api.MikrotikAPI(s)
x.login(GROOVE_USER, GROOVE_PASSWORD)

print '1. IDENTIFYING ADMIN USER.'
users = x.converse(['/user/print'])
admin = None
for user in users:
    if u'=name=admin' in user:
        admin = user
        break

if not admin:
    raise Exception('Can not locate Groove\'s ROS admin user.')

print '2. ADMIN USER IS:'
print admin

print '3. CHANGING ADMIN PASSWORD.'
password_set2 = x.converse(['/user/set', admin[1], '=password=%s' % NEW_GROOVE_PASSWORD])


print '4. IDENTIFYING GODDARD SECURITY PROFILE.'
security_profiles = x.converse(['/interface/wireless/security-profiles/print'])
goddard_security_profile = None

for sp in security_profiles:
    if u'=name=%s' % GODDARD_SECURITY_PROFILE_NAME in sp:
        goddard_security_profile = sp
        break

if not goddard_security_profile:
    raise Exception('Can not find goddard SSID\'s security profile.')

print '5. GODDARD SECURITY PROFILE IS:'
print goddard_security_profile

print '6. CHANGING GODDARD WLAN PASSWORD'

wlan_password_set = x.converse(['/interface/wireless/security-profiles/set', goddard_security_profile[1],
                                '=wpa2-pre-shared-key=%s' % NEW_GROOVE_WLAN_PASSWORD])

print wlan_password_set

print "== COMPLETE =="
