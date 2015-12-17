import socket
import argparse

import mikrotik_api

parser = argparse.ArgumentParser(description='Modify the Mikrotik devices.')
parser.add_argument('--rb750_password', help="The current admin password for the RB750.")
args = parser.parse_args()

if not args.rb750_password:
    parser.error("We need an --rb750_password value. Run -h if unsure.")

# What we know
RB750_USER = 'admin'
RB750_IP = '192.168.88.5'
RB750_PASSWORD = args.rb750_password

PORT = 8728

print '========================\n     PHASE 1 - MTU on RB750\n========================'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RB750_IP, PORT))
x = mikrotik_api.MikrotikAPI(s)
x.login(RB750_USER, RB750_PASSWORD)

print '1. GETTING THE INTERFACES ID'
interfaces = x.converse(['/interface/ethernet/print'])

ether1 = None
for interface in interfaces:
    if u'=name=ether1-gateway' in interface:
        ether1 = interface
        break

if not ether1:
    raise Exception('Ether1 interface was unable to be located.')


print '2. ETHER1 INTERFACE IS:'
print ether1

print '3. CHANGING MTU.'
password_set2 = x.converse(['/interface/ethernet/set', ether1[1], '=mtu=1360'])

print "== COMPLETE =="
