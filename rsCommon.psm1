Function Get-rsSecrets {
   if(Test-Path -Path "C:\DevOps\secrets.ps1") {
      return "C:\DevOps\secrets.ps1"
   }
   if(Test-Path -Path "C:\cloud-automation\secrets.ps1") {
      return "C:\cloud-automation\secrets.ps1"
   }
}
. (Get-rsSecrets)

if(Test-Path -Path "C:\DevOps\dedicated.csv") {
   $DedicatedData = Import-Csv -Path "C:\DevOps\dedicated.csv"
}
if(Test-Path -Path $($d.wD, $d.mR, 'PullServer.info' -join '\')) {
   . "$($d.wD, $d.mR, 'PullServer.info' -join '\')"
}

Function Get-rsServiceCatalog {
   return (Invoke-rsRestMethod -Retries 20 -TimeOut 15 -Uri $("https://identity.api.rackspacecloud.com/v2.0/tokens") -Method POST -Body $(@{"auth" = @{"RAX-KSKEY:apiKeyCredentials" = @{"username" = $($d.cU); "apiKey" = $($d.cAPI)}}} | convertTo-Json) -ContentType application/json)
}

Function Get-rsAuthToken {
   return @{"X-Auth-Token"=((Get-rsServiceCatalog).access.token.id)}
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
Function New-rsEventLogSource {
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
Function Get-rsXenInfo {
   param([string] $value)
   $base = gwmi -n root\wmi -cl CitrixXenStoreBase
   $sid = $base.AddSession("MyNewSession")
   $session = gwmi -n root\wmi -q "select * from CitrixXenStoreSession where SessionId=$($sid.SessionId)"
   $data = $session.GetValue($value).value -replace "`"", ""
   return $data
}
Function Get-rsDedicatedInfo {
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
Function Test-rsCloud {
   $base = gwmi -n root\wmi -cl CitrixXenStoreBase -ErrorAction SilentlyContinue
   if($base) {
      return $true
   }
   else {
      return $false
   }
}
Function Get-rsRole {
   if(Test-Cloud) {
      $Data = Get-rsXenInfo -value 'vm-data/provider_data/role'
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve role"
      }
      return $Data
   }
   else {
      $Data = Get-rsDedicatedInfo -Value 'role'
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve role"
      }
      return $Data
   }
}
Function Get-rsRegion {
   if(Test-Cloud) {
      $Data = Get-rsXenInfo -value 'vm-data/provider_data/region'
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve region"
      }
      return $Data
   }
   else {
      $Data = Get-rsDedicatedInfo -Value 'region'
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve region"
      }
      return $Data
   }
   
}

Function Get-rsFile {
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

Function Get-rsPublicIp {
   param (
      [uint32]$retries = 5,
      [uint32]$timeOut = 15
   )
   if(Test-Cloud) {
      $catalog = Get-rsServiceCatalog
      $region = Get-rsRegion
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

Function Get-rsAccountDetails {
   if(Test-rsCloud) {
      $currentRegion = Get-rsRegion
      $catalog = Get-rsServiceCatalog
      if(($catalog.access.user.roles | ? name -eq "rack_connect").id.count -gt 0) { $isRackConnect = $true } else { $isRackConnect = $false }
      if(($catalog.access.user.roles | ? name -eq "rax_managed").id.count -gt 0) { $isManaged = $true } else { $isManaged = $false } 
      $defaultRegion = $catalog.access.user.'RAX-AUTH:defaultRegion'
      return @{"currentRegion" = $currentRegion; "isRackConnect" = $isRackConnect; "isManaged" = $isManaged; "defaultRegion" = $defaultRegion}
   }
}

Function Test-rsRackConnect {
   if(Test-rsCloud) {
      $Data = Get-rsAccountDetails
      if($Data.isRackConnect -and ($Data.currentRegion -eq $Data.defaultRegion)) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "The server is Rackconnect and is in the default region"
         $uri = $(("https://", $Data.currentRegion -join ''), ".api.rackconnect.rackspace.com/v1/automation_status?format=text" -join '')
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

Function Test-rsManaged {
   if(Test-rsCloud) {
      $Data = Get-rsAccountDetails
      if($isManaged -or (($defaultRegion -ne $currentRegion) -and $isRackConnect)) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "Account is either managed or server is not in the default region isManaged $isManaged defaultRegion $defaultRegion Current region $currentRegion isRackConnect $isRackConnect starting to sleep"
         Start-Sleep -Seconds 60
         if((Get-rsXenInfo -value "vm-data/user-metadata/rax_service_level_automation").value.count -gt 0 ) { 
            $exists = $true 
         }
         else { 
            $exists = $false 
            Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "rax_service_level_automation is not completed."
         } 
         if ( $exists )
         {
            do {
               Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "Waiting for rax_service_level_automation."
               Start-Sleep -Seconds 30
            }
            while ( (Test-Path "C:\Windows\Temp\rs_managed_cloud_automation_complete.txt" ) -eq $false)
            Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "rax_service_level_automation complete."
         }
      } 
   }
}

Function Update-rsKnownHostsFile {
   $sshPaths = @("C:\Program Files (x86)\Git\.ssh", "C:\Windows\SysWOW64\config\systemprofile\.ssh", "C:\Windows\System32\config\systemprofile\.ssh")
   foreach($sshPath in $sshPaths) {
      if(!(Test-Path -Path $sshPath)) {
         try {
            New-Item -Path $sshPath -ItemType container
         }
         catch {
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Error -EventId 1002 -Message "Failed to create directory $sshPath `n $($_.Execption.Message)"
         }
      }
      New-Item $($sshPath, "known_hosts" -join '\') -ItemType File -Force
      Add-Content $($sshPath, "known_hosts" -join '\') -Value "github.com,192.30.252.129 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
      Add-Content $($sshPath, "known_hosts" -join '\') -Value "192.30.252.128 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
      Add-Content $($sshPath, "known_hosts" -join '\') -Value "192.30.252.131 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
      Add-Content $($sshPath, "known_hosts" -join '\') -Value "192.30.252.130 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
   }
}

Function New-rsSSHKey {
   if((Get-rsRole) -eq "Pull") {
      Start-Service Browser
      if(Test-Path -Path "C:\Program Files (x86)\Git\.ssh\id_rsa*") {
         Remove-Item "C:\Program Files (x86)\Git\.ssh\id_rsa*"
      }
      Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "Generating ssh Key"
      try {
         Start -Wait -NoNewWindow "C:\Program Files (x86)\Git\bin\ssh-keygen.exe" -ArgumentList "-t rsa -f 'C:\Program Files (x86)\Git\.ssh\id_rsa' -P """""
      }
      catch {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to generate SSH Key `n $($_.Exception.Message)"
      }
      Stop-Service Browser
   }
   return
}
   
Function Push-rsSSHKey {
   if((Get-rsRole) -eq "pull") {
      $keys = Invoke-rsRestMethod -Uri "https://api.github.com/user/keys" -Headers @{"Authorization" = "token $($d.gAPI)"} -ContentType application/json -Method GET
      $pullKeys = $keys | ? title -eq $($d.DDI, "_", $env:COMPUTERNAME -join '')
      if((($pullKeys).id).count -gt 0) {
         foreach($pullKey in $pullKeys) {
            Invoke-rsRestMethod -Uri $("https://api.github.com/user/keys", $pullKey.id -join '/') -Headers @{"Authorization" = "token $($d.gAPI)"} -ContentType application/json -Method DELETE
         }
      }
      $sshKey = Get-Content -Path "C:\Program Files (x86)\Git\.ssh\id_rsa.pub"
      $json = @{"title" = "$($d.DDI, "_", $env:COMPUTERNAME -join '')"; "key" = "$sshKey"} | ConvertTo-Json
      Invoke-rsRestMethod -Uri "https://api.github.com/user/keys" -Headers @{"Authorization" = "token $($d.gAPI)"} -Body $json -ContentType application/json -Method Post
      Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "config --system user.email $serverName@localhost.local"
      Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "config --system user.name $serverName"
   }
   Stop-Service Browser
   return
}

Function Update-rsGitConfig {
   param (
      [string][ValidateSet('global', 'system')]$scope = 'system',
      [string]$attribute,
      [string]$value
   )
   try {
      start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "config $("--", $scope -join '') $attribute $value"
   }
   catch {
      Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to update gitconfig file `n $($_.Exception.Message)"
   }
}




function Test-rsRegistryValue {
   
   param (
      
      [parameter(Mandatory=$true)]
      [ValidateNotNullOrEmpty()]$Path,
      
      [parameter(Mandatory=$true)]
      [ValidateNotNullOrEmpty()]$Value
   )
   
   if(Test-Path $Path){
      
      try {
         
         Get-ItemProperty $Path -Name $Value -ErrorAction Stop | Out-Null
         return $true
         
      }
      
      catch {
         
         return $false
         
      }
      
   }
   else{return $false}
}


function Get-rsRegistryValue {
   
   param (
      
      [parameter(Mandatory=$true)]
      [ValidateNotNullOrEmpty()]$Path,
      
      [parameter(Mandatory=$true)]
      [ValidateNotNullOrEmpty()]$Value
   )
   
   if(Test-Path $Path){
      
      try {
         
         Get-ItemProperty $Path -Name $Value -ErrorAction Stop | Select-Object -ExpandProperty $Value -ErrorAction Stop
         
      }
      
      catch {}
      
   }
}

<#

Usage

Test-rsRegistryValue returns boolean

Test-rsRegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value "AUOptions"


Get-rsRegistryValue returns the value

Get-rsRegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value "AUOptions"

#>