#+++++++++___
#++ ((-))  o - - ___
#+++++++++__|     o - -___
# Windows Syslog Agent   o \
# Written: Lee Mazzoleni  o \
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


"Logging service started"

$time = Get-Date
$hr = $time.TimeOfDay.Hours
$min = $time.TimeOfDay.Minutes
$day = $time.DayOfYear
$yr = $time.Year

$ip = "192.168.68.153"  # rsyslog server 
$port = 514
$address = [system.net.IPAddress]::Parse($ip)
$server = New-Object System.Net.IPEndPoint $address, $port

$new_socket = [System.Net.Sockets.AddressFamily]::InterNetwork 
$socket_type = [System.Net.Sockets.SocketType]::Dgram 
$protocol = [System.Net.Sockets.ProtocolType]::UDP 
$sock = New-Object System.Net.Sockets.Socket $new_socket, $socket_type, $protocol
$sock.TTL = 90

# Check to see which logging facilities contain entries (inactive services will produce 0 logs)
# Facilities with log entries will be appended to the $log_pool array for later iterations
$log_pool = @()
Get-WinEvent -ListLog * | ForEach-Object { 
	if ($_.RecordCount -gt 0) {
		$log_pool += $_.LogName
	}
}

while ("ok") {
	$current_time = Get-Date
	$current_hr  = $current_time.TimeOfDay.Hours
	$current_min = $current_time.TimeOfDay.Minutes
    $current_day = $current_time.DayOfYear
    $current_year = $current_time.Year
	if ($min -eq $current_min) {
		sleep 60;
	} else {
		$time = $current_time;
		$previous_min = $time.TimeOfDay.Minutes - 1
		$hour = $time.TimeOfDay.Hours
        $day = $time.DayOfYear
        $year = $time.Year
		if ($previous_min -eq -1) {
			$previous_min = 59;
		} ElseIf ($($hour - 1) -eq -1)  {
			$hour = 23;
		} 
		#$target_time = -join $($hour,':',$previous_min)
		$event_pool = @()
        $log_pool | ForEach-Object {
            Get-WinEvent -LogName "$_" -MaxEvents 20 | Sort-Object TimeCreated | Where-Object { $_.TimeCreated.Hour -eq $hour -and $_.TimeCreated.Minute -eq $previous_min -and $_.TimeCreated.DayOfYear -eq $day -and $_.TimeCreated.Year -eq $year  } | ForEach-Object {
                $event_pool += $_
            }
        }    
        if ($event_pool.Count -ne 0) {
            $arr_count = $event_pool.Count
            -join $("Found ",$arr_count," log entries from the previous minute.")
            $event_pool = $event_pool | Sort-Object { $_.TimeCreated }
            $event_pool | ForEach-Object {           
                $message = $_.Message -split "`n"
                $message = $message[0]
                $event_id = $_.Id
                #get acount name from authentication logs
                if ($event_id -eq 4672 -or $event_id -eq 4634) {
                    $user = $($($_.Message | findstr Name) -split "`t")[3]
                } ElseIf ($event_id -eq 4624 -or $event_id -eq 4648) {
                    $user = $($($($($_.Message | findstr Name) -split "`n")[1]) -split "`t")[3]
                } Else {
                    $user = $_.UserId
                    if (!$user) {
                        $user = "n/a"
                    }
                }
                $source = $_.ProviderName
                $hname = $_.MachineName
                $severity = $_.LevelDisplayName
                $timestamp = $_.TimeCreated
                $log = -join $($hname,' - ',$timestamp,' - src_app:','"',$source,'" ','src_user:','"',$user,'" ','msg:','"',$message,'" ','eventID:','"',$event_id,'" ','type:','"',$severity,'" ')
                $Enc = [System.Text.Encoding]::ASCII
                $Buffer = $Enc.GetBytes($log)
	            $sock.Connect($server)
	            $sendit = $sock.Send($Buffer)
            } 
        } else { 
                echo "No logs this time, going to sleep."
        }
        sleep 60;
	}
}
