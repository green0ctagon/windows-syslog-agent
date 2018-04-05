# windows-syslog-agent
This is a simple Windows event forwarder intended for compatibility with standard UDP syslog/rsyslog.  
It has been successfully tested on Win7 and Win2008.

This script collects, sorts, parses, and forwards events from each of the host's logging facilities (see "Get-WinEvent -ListLog *").

Just add the IP and Port of your syslog server to the script, and it is ready to go.  Be sure to run as admin (otherwise the script won't be able to access "Security" and other other sensitive logging facilities.

If you are running this in a restricted environment:
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File win_syslog.ps1
