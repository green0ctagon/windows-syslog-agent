# [!] Windows Syslog Agent
# [$] Forward Windows Events via UDP in JSON format, designed for compatibility with Syslog/Rsyslog
# [$] Written: Lee Mazz


# [*] New Features:
	# 1.) Event queuing functionality for offline logging has been added
		# [x] At runtime, if the program cannot validate the connection with the syslog server, it will log events locally (to a file).  The next time the program runs and can positively confirm connectivity with the syslog server all previously-queued logs will get forwarded.
		# [x] This feature is designed to accomodate mobile workstations such as laptops that may be used offsite
		# [x] This feature ensures that no events get dropped due to connectivity issues
	# 2.) Program has been modularized


function getStatus () {

    $ip = '192.168.11.12'
    $offlineLogs = 'queued.log'

    # check the connectivity to the syslog server before blasting udp at it
    ping -n 1 $ip | Out-Null

    if ($?) {
    
        # if the connection status is verified, check if there is a queued log file that needs to be forwarded
        ls $offlineLogs | Out-Null
    
        if ($?) {
            $port = 2514
            $address = [system.net.IPAddress]::Parse($ip)
            $server = New-Object System.Net.IPEndPoint $address, $port
            $new_socket = [System.Net.Sockets.AddressFamily]::InterNetwork
            $socket_type = [System.Net.Sockets.SocketType]::Dgram
            $protocol = [System.Net.Sockets.ProtocolType]::UDP
            $sock = New-Object System.Net.Sockets.Socket $new_socket, $socket_type, $protocol
            $sock.TTL = 90
            $Enc = [System.Text.Encoding]::ASCII
            # send all the queued logs to the SIEM
            gc $offlineLogs | ForEach-Object {
                $Buffer = $Enc.GetBytes($_)
                $sock.Connect($server)
                $sendit = $sock.Send($Buffer)
            }
            # remove the queued logs from disk once they have been forwarded to SIEM
            ri $offlineLogs -ea 0
        }
        
        #after forwarding any queued logs, resume the normal real-time forwarding
        logRemotely
    } else {
        logLocally
    }
}


function logRemotely () {

    $providers = New-Object System.Collections.ArrayList
    Get-WinEvent -ListLog * | ForEach-Object {
            if ($_.RecordCount -gt 0) {
                    $providers.Add($_.LogName) | Out-Null
            }
    }

    $events = New-Object System.Collections.ArrayList
    foreach ($fac in ($providers)) {
        Get-WinEvent -FilterHashtable @{Logname="$fac";StartTime=$time} -ea 0 | ForEach-Object { $events.Add($_) | Out-Null }
    }

    if ($events.Count -gt 0) {

        $ip = "10.2.113.150"
        $port = 2514
        $address = [system.net.IPAddress]::Parse($ip)
        $server = New-Object System.Net.IPEndPoint $address, $port
        $new_socket = [System.Net.Sockets.AddressFamily]::InterNetwork
        $socket_type = [System.Net.Sockets.SocketType]::Dgram
        $protocol = [System.Net.Sockets.ProtocolType]::UDP
        $sock = New-Object System.Net.Sockets.Socket $new_socket, $socket_type, $protocol
        $sock.TTL = 90
    
        # Un-comment the two lines below if you are implementing this agent on >50 hosts
        #$sleepyTime = Get-Random(1..10)tail 
        #sleep $sleepytime

        $propertiez = @("Message","Id","ProviderName","Logname","ProcessId","MachineName","UserId","TimeCreated","LevelDisplayName","TaskDisplayName","KeywordsDisplayNames")
        $events = $events | Sort-Object { $_.TimeCreated }
        $events | ForEach-Object {
            $log = New-Object System.Object 
            foreach ($prop in ($propertiez)) { 
	            $value = $_.$prop -replace '`r`n','`n'
                $value = $value -replace '`n',' '
                $value = $value -replace '`t',' '
                $value = $value -replace '\s+',' '
                $value = $value -replace '[{}]',''
                $value = $value -replace '"','~'
                $value = $value -replace "'",'~'
                $value = $value.replace('\','/')
                if (!$value) {
                    $value = 'null'
                } ElseIf ($prop -ne "TimeCreated") {
		            $log | Add-Member NoteProperty $prop $value
	            } else {
		            [string]$value = $_.TimeCreated
		            $log | Add-Member NoteProperty $prop $value
	            }
            }
        
            $jsonLog = ConvertTo-Json -InputObject $log
            $jsonLog = $jsonLog -replace '`r`n','`n'
            $jsonLog = $jsonLog -replace '`n',' '
            $jsonLog = $jsonLog -replace '`t',' '
            $jsonLog = $jsonLog -replace '\s+',' '
            $jsonLog = ((($jsonLog.replace("\n"," ")).replace("\t"," ")).replace("\r"," "))
            #$jsonLog

            # Send the new event log to the syslog/cloud collector server        
            $Enc = [System.Text.Encoding]::ASCII
            $Buffer = $Enc.GetBytes($jsonLog)
            $sock.Connect($server)
            $sendit = $sock.Send($Buffer)
        }
    }
}


function logLocally () {
    
    $providers = New-Object System.Collections.ArrayList
    Get-WinEvent -ListLog * | ForEach-Object {
            if ($_.RecordCount -gt 0) {
                    $providers.Add($_.LogName) | Out-Null
            }
    }

    $events = New-Object System.Collections.ArrayList
    foreach ($fac in ($providers)) {
        Get-WinEvent -FilterHashtable @{Logname="$fac";StartTime=$time} -ea 0 | ForEach-Object { $events.Add($_) | Out-Null }
    }

    if ($events.Count -gt 0) {
    
        # Un-comment the two lines below if you are implementing this agent on >50 hosts
        #$sleepyTime = Get-Random(1..10)
        #sleep $sleepytime

        $propertiez = @("Message","Id","ProviderName","Logname","ProcessId","MachineName","UserId","TimeCreated","LevelDisplayName","TaskDisplayName","KeywordsDisplayNames")
        $events = $events | Sort-Object { $_.TimeCreated }
        $events | ForEach-Object {
            $log = New-Object System.Object
            foreach ($prop in ($propertiez)) { 
	            $value = $_.$prop -replace '`r`n','`n'
                $value = $value -replace '`n',' '
                $value = $value -replace '`t',' '
                $value = $value -replace '\s+',' '
                $value = $value -replace '[{}]',''
                $value = $value -replace '"','~'
                $value = $value -replace "'",'~'
                $value = $value.replace('\','/')
                if (!$value) {
                    $value = 'null'
                } ElseIf ($prop -ne "TimeCreated") {
		            $log | Add-Member NoteProperty $prop $value
	            } else {
		            [string]$value = $_.TimeCreated
		            $log | Add-Member NoteProperty $prop $value
	            }
            }
            $jsonLog = ConvertTo-Json -InputObject $log
            $jsonLog = $jsonLog -replace '`r`n','`n'
            $jsonLog = $jsonLog -replace '`n',' '
            $jsonLog = $jsonLog -replace '`t',' '
            $jsonLog = $jsonLog -replace '\s+',' '
            $jsonLog = ((($jsonLog.replace("\n"," ")).replace("\t"," ")).replace("\r"," "))
            # log is stored locally in "queued.log" - the contents of this file are forwarded to the syslog server as soon as a connection to the server can be confirmed by ping probes 
            $jsonLog >> queued.log
        }
    }
}


$global:time = (Get-Date) - (New-TimeSpan -Minutes 1)
getStatus
Remove-Variable -Name * -ErrorAction SilentlyContinue
[gc]::collect()
