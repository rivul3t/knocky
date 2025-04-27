# knocky
This is my simple implementation of port knocking algo(https://en.wikipedia.org/wiki/Port_knocking).  
In this algo, remote host must attempt to establish connection(may not be successful)
to a specific sequence of ports on the server. Once the correct sequence is detected, the server will open a designated port for the remote host.

environments:  
TIMEOUT - max time between port knocks(between neighbors, not first and last)
PORT_SEQUENCE - required sequence
PORT_TO_OPEN - port that will be opened
DURATION_TO_KEEP_OPEN - the time that port will be open