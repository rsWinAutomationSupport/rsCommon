if(Test-Path -Path "C:\DevOps\secrets.ps1") {
   . "C:\DevOps\secrets.ps1"
}
if(Test-Path -Path "C:\cloud-automation\secrets.ps1") {
   . "C:\cloud-automation\secrets.ps1"
}
if(Test-Path -Path "C:\DevOps\dedicated.csv") {
   $DedicatedData = Import-Csv -Path "C:\DevOps\dedicated.csv"
}
if(Test-Path -Path $($d.wD, $d.mR, 'PullServer.info' -join '\')) {
   . "$($d.wD, $d.mR, 'PullServer.info' -join '\')"
}

Function Get-Secrets {
   if(Test-Path -Path "C:\DevOps\secrets.ps1") {
      return "C:\DevOps\secrets.ps1"
   }
   if(Test-Path -Path "C:\cloud-automation\secrets.ps1") {
      return "C:\cloud-automation\secrets.ps1"
   }
}
Function Get-ServiceCatalog {
   return (Invoke-rsRestMethod -Retries 20 -TimeOut 15 -Uri $("https://identity.api.rackspacecloud.com/v2.0/tokens") -Method POST -Body $(@{"auth" = @{"RAX-KSKEY:apiKeyCredentials" = @{"username" = $($d.cU); "apiKey" = $($d.cAPI)}}} | convertTo-Json) -ContentType application/json)
}

Function Invoke-rsRestMethod {
   param (
      [string][ValidateNotNull()]$Uri,
      [string][ValidateSet('GET', 'PUT', 'POST', 'DELETE', ignorecase=$False)]$Method,
      [string]$Body,
      [hashtable]$Headers,
      [string][ValidateSet('application/json', 'application/xml', ignorecase=$False)]$ContentType = "application/json",
      [uint32]$Retries = 2,
      [uint32]$TimeOut = 10
      
   )
   $i = 0
   do {
      if($i -ge $Retries) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve service catalog, reached maximum retries"
         return $null
      }
      if($Method.ToLower() -eq "post" -or $Method.ToLower() -eq "put") {
         try {
            $Data =  (Invoke-RestMethod -Uri $Uri -Method $Method.ToUpper() -Body $Body -Headers $Headers -ContentType $ContentType -ErrorAction SilentlyContinue)
         }
         catch {
            if(($error[0].Exception.Response.StatusCode.value__) -ge 500) {
               Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "API call Failed `n $($_.Exception.Message)"
            }
            else {
               Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "API call Failed `n $($_.Exception.Message)"
               break
            }
         }
      }
      else {
         try {
            $Data =  (Invoke-RestMethod -Uri $Uri -Method $Method.ToUpper() -Headers $Headers -ContentType $ContentType -ErrorAction SilentlyContinue)
         }
         catch {
            if(($error[0].Exception.Response.StatusCode.value__) -ge 500) {
               Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "API call Failed `n $($_.Exception.Message)"
            }
            else {
               Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "API call Failed `n $($_.Exception.Message)"
               break
            }
         }
      }
      $i++
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 10002 -Message "Failed API call trying again in $timeOuts seconds`n $($_.Exception.Message)"
         if($i -ge $Retries) {
            return $null
         }
         else {
            Start-Sleep -Seconds $TimeOut
         }
      }
   }
   while($Data -eq $null)
   return $Data
}
Function New-EventLogSource {
   param (
      [string]$logSource
   )
   if($logSource -ne $null) {
      if([System.Diagnostics.EventLog]::SourceExists($logSource)) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Create-EventLog was passed a null value for logsource"
      }
      if($logSource -eq $true) {
         return
      }
      else {
         New-EventLog -LogName "DevOps" -Source $logSource
      }
   }
}
Function Get-XenInfo {
   param([string] $value)
   $base = gwmi -n root\wmi -cl CitrixXenStoreBase
   $sid = $base.AddSession("MyNewSession")
   $session = gwmi -n root\wmi -q "select * from CitrixXenStoreSession where SessionId=$($sid.SessionId)"
   $data = $session.GetValue($value).value -replace "`"", ""
   return $data
}
Function Get-DedicatedInfo {
   param (
      [string]$Value
   )
   if(Test-Path -Path $($d.wD, $d.mR, "dedicated.csv" -join '\')) {
      $Data = Import-Csv $($d.wD, $d.mR, "dedicated.csv" -join '\')
      if($Data.$($Value) -ne $null) {
         return $Data.$($Value)
      }
      else {
         return $null
      }
   }
   return $Data.$($Value)
}
Function Test-Cloud {
   $base = gwmi -n root\wmi -cl CitrixXenStoreBase -ErrorAction SilentlyContinue
   if($base) {
      return $true
   }
   else {
      return $false
   }
}
Function Get-Role {
   if(Test-Cloud) {
      $Data = Get-XenInfo -value 'vm-data/provider_data/role'
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve role"
      }
      return $Data
   }
   else {
      $Data = Get-DedicatedInfo -Value 'role'
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve role"
      }
      return $Data
   }
}
Function Get-Region {
   if(Test-Cloud) {
      $Data = Get-XenInfo -value 'vm-data/provider_data/region'
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve region"
      }
      return $Data
   }
   else {
      $Data = Get-DedicatedInfo -Value 'region'
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve region"
      }
      return $Data
   }
   
}

Function Get-File {
   param ( 
      [string][ValidateNotNull()]$url, 
      [string][ValidateNotNull()]$path,
      [uint32]$retries = 2,
      [uint32]$timeOut = 10
   )
   $i = 0
   $webclient = New-Object System.Net.WebClient
   do {
      if($i -ge $retries) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to download file from $url retry threshold exceeded"
         return
      }
      try {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "Attempting to download $url."
         $webclient.DownloadFile($url,$path)
         if(Test-Path -Path $path -eq $true) {
            $i = $retries
         }
      }
      catch {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "Failed to download $url sleeping for $timeOut seconds then trying again. `n $($_.Exception.Message)"
         $i++
         Start-Sleep -Seconds $timeOut
      }
   }
   while ($i -lt $retries)
   return
}

Function Get-PublicIp {
   param (
      [uint32]$retries = 5,
      [uint32]$timeOut = 15
   )
   if(Test-Cloud) {
      $catalog = Get-ServiceCatalog
      $region = Get-Region
      $i = 0
      $uri = (($catalog.access.serviceCatalog | ? name -eq "cloudServersOpenStack").endpoints | ? region -eq $region).publicURL
      do {
         if($i -ge $retries) { 
            Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Retry threshold reached, stopping retry loop."
            break 
         }
         try {
            Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "Retrieving Public address $accessIPv4"
            $Data = (((Invoke-rsRestMethod -Retries $retries -TimeOut $timeOut -Uri $($uri, "servers/detail" -join '/') -Method GET -Headers @{"X-Auth-Token"=($catalog.access.token.id)} -ContentType application/json).servers) | ? { $_.name -eq $env:COMPUTERNAME}).accessIPv4
         }
         catch {
            Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "Failed to retrieve Public address, sleeping for $timeOut seconds then trying again. `n $($_.Exception.Message)"
            $i++
            Start-Sleep -Seconds $timeOut
         }
      }
      while ($i -lt $retries)
      if($Data) {
         return $Data
      }
      else {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "Failed to retrieve public ip address, sleeping for $timeOut seconds then trying again."
         return $Data
      }
   }
   else {
      if(Test-Path -Path $($d.wD, $d.mR, "dedicated.csv" -join '\')) {
         $Data = (Import-Csv $($d.wD, $d.mR, "dedicated.csv" -join '\') | ? ServerName -eq $env:COMPUTERNAME).PublicIP
      }
      return $Data
   }
   if($Data) {
      return $Data
   }
   else {
      Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "Failed to retrieve public ip address, sleeping for $timeOut seconds then trying again."
      return $Data
   }
}
Function Test-RackConnect {
   if(Test-Cloud) {
      $currentRegion = Get-Region
      $catalog = Get-ServiceCatalog
      if(($catalog.access.user.roles | ? name -eq "rack_connect").id.count -gt 0) { $isRackConnect = $true } else { $isRackConnect = $false }
      if(($catalog.access.user.roles | ? name -eq "rax_managed").id.count -gt 0) { $isManaged = $true } else { $isManaged = $false } 
      $defaultRegion = $catalog.access.user.'RAX-AUTH:defaultRegion'
      Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "Checking Rackconnect: Current region $currentRegion isRackconnect $isRackConnect isManaged $isManaged defaultRegion $defaultRegion"
      if($isRackConnect -and ($currentRegion -eq $defaultRegion)) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "The server is Rackconnect and is in the default region"
         $uri = $(("https://", $currentRegion -join ''), ".api.rackconnect.rackspace.com/v1/automation_status?format=text" -join '')
         do {
            $rcStatus = Invoke-rsRestMethod -Uri $uri -Method GET -ContentType application/json
            Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "RackConnect status is: $rcStatus"
            Start-Sleep -Seconds 10
         }
         while ($rcStatus -ne "DEPLOYED")
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "RackConnect status is: $rcStatus"
      }
   }
}

Function Test-Managed {
   if(Test-Cloud) {
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Checking to see if account is managed"
      $currentRegion = Get-Region
      if($Global:isManaged -or (($Global:defaultRegion -ne $currentRegion) -and $Global:isRackConnect)) {
         Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Account is either managed or server is not in the default region isManaged $Global:isManaged defaultRegion $Global:defaultRegion Current region $currentRegion isRackConnect $Global:isRackConnect starting to sleep"
         Start-Sleep -Seconds 60
         $base = gwmi -n root\wmi -cl CitrixXenStoreBase 
         $sid = $base.AddSession("MyNewSession") 
         $session = gwmi -n root\wmi -q "select * from CitrixXenStoreSession where SessionId=$($sid.SessionId)" 
         if( $session.GetValue("vm-data/user-metadata/rax_service_level_automation").value.count -gt 0 ) { $exists = $true }
         else { 
            $exists = $false 
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "rax_service_level_automation is not completed."
         } 
         if ( $exists )
         {
            do {
               Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Waiting for rax_service_level_automation."
               Start-Sleep -Seconds 30
            }
            while ( (Test-Path "C:\Windows\Temp\rs_managed_cloud_automation_complete.txt" ) -eq $false)
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "rax_service_level_automation complete."
         }
      } 
   }
}