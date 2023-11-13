# icup

ICMP? Not quite, I See You P

ICUP is an ICMP C2 server for usage in Red Vs Blue Competitions.

**Client Usage**:<br>
To operate the client, the interface for the listener (line 149 of the client) may need to be altered to match the primary interface of the machine. After this, a compiled Go binary or _go run client.go_ will run the client, root permissions needed. 

**Server Usage**:<br>
To operate the client, the interface for the listener (line 149 of the client) may need to be altered to match the primary interface of the machine. After this, a compiled Go binary or _go run server.go_ will run the server, root permissions needed.

For competitions, GenerateTargets.py can be used to create a targets file that can be read by the server. It will allow for and number of boxes and any number of teams, and creates a view of all active or inactive clients. 

Once the server is started, the _load_ command will create the clients, and _checkalive_ will show all clients, alive or dead. _ls_ will show all IDs to IP mappings, and commands can be executed client by client, team by team, or machine by machine. 
