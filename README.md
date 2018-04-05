# windows-syslog-agent
This is a simple Windows event forwarder designed to be compatible with standard UDP syslog/rsyslog servers.  
It has been successfully tested on Win7 and Win2008 systems.

This script collects, sorts, parses, and forwards events from each of the host's logging facilities (see "Get-WinEvent -ListLog *").

Just add the IP and Port of your syslog/rsyslog server to the script, and it is ready to go.
Be sure to run as admin (otherwise the script won't be able to access "Security" and other other sensitive logging facilities).

When you run the script, it will begin polling in 60-second intervals.
![alt text](http://81.4.111.62/ScreenShots/logger.PNG)

This is the current logging format.  Each line is tagged with the source hostname in case you are collecting logs from multiple sources. (I've blocked out my hostname from each line, and my username from the authentication logs.)
![alt text](http://81.4.111.62/ScreenShots/logs.PNG)

I would recommend running this program as a scheduled task that starts upon boot, otherwise it will only run when a user is logged in.

Also, I'm a Linux guy so please excuse this script's lack of elegance.

