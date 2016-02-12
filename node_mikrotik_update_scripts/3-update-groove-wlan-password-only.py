import socket
import argparse

import mikrotik_api

parser = argparse.ArgumentParser(description='Modify the Mikrotik devices.')

parser.add_argument('--groove_password', help="The current admin password for the Groove.")
parser.add_argument('--new_groove_wlan_password', help="The new password for the hidden `goddard` SSID.")

args = parser.parse_args()

if not args.groove_password or not args.new_groove_wlan_password:
    parser.error("All arguments need to be provided... Run -h if unsure.")

# What we know
GROOVE_USER = 'admin'
GROOVE_IP = '192.168.88.10'
GROOVE_PASSWORD = args.groove_password

PORT = 8728

# The name of the security profile attached to the "goddard" hidden SSID.
GODDARD_SECURITY_PROFILE_NAME = 'goddard'

# What we are going to set
NEW_GROOVE_WLAN_PASSWORD = args.new_groove_wlan_password


print '========================\n  PHASE 1 - GROOVE WIFI\n========================'

# Set up the socket, connect, login...
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((GROOVE_IP, PORT))
x = mikrotik_api.MikrotikAPI(s)
x.login(GROOVE_USER, GROOVE_PASSWORD)

print '1. IDENTIFYING GODDARD SECURITY PROFILE.'
security_profiles = x.converse(['/interface/wireless/security-profiles/print'])
goddard_security_profile = None

for sp in security_profiles:
    if u'=name=%s' % GODDARD_SECURITY_PROFILE_NAME in sp:
        goddard_security_profile = sp
        break

if not goddard_security_profile:
    raise Exception('Can not find goddard SSID\'s security profile.')

print '2. GODDARD SECURITY PROFILE IS:'
print goddard_security_profile

print '3. CHANGING GODDARD WLAN PASSWORD'

wlan_password_set = x.converse(['/interface/wireless/security-profiles/set', goddard_security_profile[1],
                                '=wpa2-pre-shared-key=%s' % NEW_GROOVE_WLAN_PASSWORD])

print wlan_password_set

print "== COMPLETE =="
