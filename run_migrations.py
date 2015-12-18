# Custom migration script as there's no
# migration script for this stuff apparently.

import data

data.connect()
data.create_tables()
