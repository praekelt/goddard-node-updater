import csv
import data

data.connect()

reader = csv.reader(open('fixtures.csv', 'r'))

for node_id, ip_address, site_name in reader:
    nsm, created = data.NodeSiteMeta.create_or_get(node_id=node_id)
    nsm.ip_address = ip_address
    nsm.site_name = site_name
    nsm.save()
