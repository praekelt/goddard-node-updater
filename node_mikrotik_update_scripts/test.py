import socket

import mikrotik_api

PORT = 8728

# The name of the security profile attached to the "goddard" hidden SSID.
GODDARD_SECURITY_PROFILE_NAME = 'goddard'  # "goddard" in production

# Set up the socket, connect, login...
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.88.10', PORT))
x = mikrotik_api.MikrotikAPI(s)
x.login('admin', '3PywaQrEQmwFhHmyks')


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

#x = x.converse(['/interface/wireless/security-profiles/set', goddard_security_profile[1],
#                '=wpa2-pre-shared-key=%s' % 'dncPz87wDTmzkX5Ab7'])

#print x

print "== COMPLETE =="
