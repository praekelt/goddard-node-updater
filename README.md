# Goddard Node Updater

The Goddard Node Updater is a long running python application that attempts to communicate with Goddard Nodes, gather data from the Nodes, Check their health, apply any neccessary fixes and reports on their status via Slack and email.


The script is started quite simply:

$ python node_updater.py   <- Attempts to connect to and run on all Nodes.

or 

$ python node_updater.py 15    <- Attempts to connect to and run on Node #15  

The Node Updater needs to be able to connect to and query a local database of Nodes and is therefore designed to be run on the Goddard Hub Server.


