Function Get-rsSecrets {
   if(Test-Path -Path "C:\DevOps\secrets.ps1") {
      return "C:\DevOps\secrets.ps1"
   }
}
. (Get-rsSecrets)

if(Test-Path -Path $("C:\DevOps", $d.mR, 'PullServerinfo.ps1' -join '\')) {
   . "$("C:\DevOps", $d.mR, 'PullServerinfo.ps1' -join '\')"
}

Function Get-rsServiceCatalog {
   return (Invoke-rsRestMethod -Retries 20 -TimeOut 15 -Uri $("https://identity.api.rackspacecloud.com/v2.0/tokens") -Method POST -Body $(@{"auth" = @{"RAX-KSKEY:apiKeyCredentials" = @{"username" = $($d.rs_username); "apiKey" = $($d.rs_apikey)}}} | convertTo-Json) -ContentType application/json)
}

Function Get-rsAuthToken {
   return @{"X-Auth-Token"=((Get-rsServiceCatalog).access.token.id)}
}

Function New-rsEventLogSource {
   param (
      [string]$logSource
   )
   if($logSource -ne $null) {
      if([System.Diagnostics.EventLog]::SourceExists($logSource)) {
         return
      }
      else {
         New-EventLog -LogName "DevOps" -Source $logSource
      }
   }
   else {
      Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Create-EventLog was passed a null value for logsource"
      return
   }
}

New-rsEventLogSource -logSource rsCommon

Function Get-rsDetailsServers
{
   $catalog = Get-rsServiceCatalog
   $endpoints = ($catalog.access.serviceCatalog | ? name -eq "cloudServersOpenStack").endpoints.publicURL
   foreach( $endpoint in $endpoints )
   {
      $temp = (Invoke-rsRestMethod -Uri $($endpoint,"servers/detail" -join "/") -Method GET -Headers $(Get-rsAuthToken) -ContentType application/json)
      $servers = $servers,$temp
   }
   return ( ($servers.servers | ? {@("Deleted", "Error", "Unknown") -notcontains $_.status}) )
}

Function Invoke-rsRestMethod {
   param (
      [string][ValidateNotNull()]$Uri,
      [string][ValidateSet('GET', 'PUT', 'POST', 'DELETE', ignorecase=$true)]$Method,
      [string]$Body,
      [hashtable]$Headers,
      [string][ValidateSet('application/json', 'application/xml', ignorecase=$true)]$ContentType = "application/json",
      [uint32]$Retries = 2,
      [uint32]$TimeOut = 10
      
   )
   $i = 0
   $ContentType = $ContentType.ToLower()
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
            if( (($error[0].Exception.Response.StatusCode.value__) -ge 500) -or ($Error[0].Exception.Message -like "The remote name could not be resolved:*") ) {
               Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "API call Failed `n $Method`: $Uri `n $Body `n $($_.Exception.Message) `n $($_.ErrorDetails.Message)"
            }
            else {
               Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "API call Failed `n $Method`: $Uri `n $Body `n $($_.Exception.Message) `n $($_.ErrorDetails.Message)"
               break
            }
         }
      }
      else {
         try {
            $Data =  (Invoke-RestMethod -Uri $Uri -Method $Method.ToUpper() -Headers $Headers -ContentType $ContentType -ErrorAction SilentlyContinue)
         }
         catch {
            if( (($error[0].Exception.Response.StatusCode.value__) -ge 500) -or ($Error[0].Exception.Message -like "The remote name could not be resolved:*") ) {
               Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "API call Failed `n $Method`: $Uri `n $Body `n $($_.Exception.Message) `n $($_.ErrorDetails.Message)"
            }
            else {
               Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "API call Failed `n $Method`: $Uri `n $Body `n $($_.Exception.Message) `n $($_.ErrorDetails.Message)"
               break
            }
         }
      }
      $i++
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 10002 -Message "Failed API call trying again in $TimeOut seconds`n $($_.Exception.Message)"
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
         return
      }
      else {
         New-EventLog -LogName "DevOps" -Source $logSource
      }
   }
   else {
      Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Create-EventLog was passed a null value for logsource"
      return
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
   . (Get-rsSecrets)
   if(Test-Path -Path $("C:\DevOps", $d.mR, "dedicated.csv" -join '\')) {
      $Data = Import-Csv $("C:\DevOps", $d.mR, "dedicated.csv" -join '\')
      if(($Data) -ne $null) {
         return $Data
      }
   }
   if((Test-Path -Path "C:\DevOps\dedicated.csv")  -and (!(Test-Path -Path $("C:\DevOps", $d.mR, "dedicated.csv" -join '\')))) {
      $Data = Import-Csv "C:\DevOps\dedicated.csv"
      if(($Data) -ne $null) {
         return $Data
      }
   }
   return $null
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
   param (
      [string]$Value
   )
   if(Test-rsCloud) {
      $Data = Get-rsXenInfo -value 'vm-data/user-metadata/rax_dsc_config'
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve role"
      }
      if($Data -eq "rsPullServer.ps1") {
         return "pull"
      }
      else {
         return $Data
      }
   }
   else {
      $Data = Get-rsDedicatedInfo
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve role"
      }
      if((($Data | ? {$_.name -eq $Value}).rax_dsc_config) -eq "rsPullServer.ps1") {
         return "pull"
      }
      else {
         return ($Data | ? {$_.name -eq $Value}).rax_dsc_config
      }
   }
}
Function Get-rsRegion {
   param (
      [string]$Value
   )
   if(Test-rsCloud) {
      $Data = Get-rsXenInfo -value 'vm-data/provider_data/region'
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve region"
      }
      return $Data
   }
   else {
      $Data = Get-rsDedicatedInfo
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve region"
      }
      return ($Data | ? { $_.name -eq $Value} ).region
   }
   
}

Function Get-rsPullServerName {
   if(Test-rsCloud) {
      . "$("C:\DevOps", $d.mR, 'PullServerinfo.ps1' -join '\')"
      $Data = $pullServerInfo.pullServerName
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve PullServerName"
      }
      return $Data
   }
   else {
      $Data = Get-rsDedicatedInfo
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Failed to retrieve role"
      }
      return ($Data | ? { $_.role -eq "pull"} ).name
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
         if((Test-Path -Path $path) -eq $true) {
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

Function Get-rsAccessIPv4 {
   param (
      [uint32]$retries = 5,
      [uint32]$timeOut = 15
   )
   if(Test-rsCloud) {
      $catalog = Get-rsServiceCatalog
      $region = Get-rsRegion -Value $env:COMPUTERNAME
      $i = 0
      $uri = (($catalog.access.serviceCatalog | ? name -eq "cloudServersOpenStack").endpoints | ? region -eq $region).publicURL
      do {
         if($i -ge $retries) { 
            Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Retry threshold reached, stopping retry loop."
            break 
         }
         try {
            Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "Retrieving Public address $accessIPv4"
            $Data = (((Invoke-rsRestMethod -Uri $($uri, "servers/detail" -join '/') -Retries $retries -TimeOut $timeOut -Method GET -Headers (Get-rsAuthToken) -ContentType application/json).servers) | ? { $_.name -eq $env:COMPUTERNAME}).accessIPv4
            if($Data -ne $null) {
               return $Data
               
            }
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
      if(Test-Path -Path $("C:\DevOps", $d.mR, "dedicated.csv" -join '\')) {
         $Data = ((Get-rsDedicatedInfo) | ? { $_.name -eq $env:COMPUTERNAME} ).accessIPv4
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
      $currentRegion = Get-rsRegion -Value $env:COMPUTERNAME
      if ((Get-rsRole -value $env:COMPUTERNAME) -eq 'pull'){
          $catalog = Get-rsServiceCatalog
          if(($catalog.access.user.roles | ? name -eq "rack_connect").id.count -gt 0) { $isRackConnect = $true } else { $isRackConnect = $false }
          if(($catalog.access.user.roles | ? name -eq "rax_managed").id.count -gt 0) { $isManaged = $true } else { $isManaged = $false } 
          $defaultRegion = $catalog.access.user.'RAX-AUTH:defaultRegion'
      }
      else {
        $currentRegion = Get-rsRegion -Value $env:COMPUTERNAME
        $isRackConnect = $($pullServerInfo.isRackConnect)
        $isManaged = $($pullServerInfo.isManaged)
        $defaultRegion = $($pullServerInfo.defaultRegion)
      }
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
        while(@("DEPLOYED", "FAILED") -notcontains $rcStatus)
        Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "RackConnect status is: $rcStatus"
        }
    }
}

Function Test-rsManaged {
    if(Test-rsCloud) {
        if((Get-rsXenInfo -value "vm-data/user-metadata/rax_service_level_automation").value.count -gt 0 ) { 
            $exists = $true 
        }
        else { 
            $exists = $false 
            Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "Testing for rax_service_level_automation."
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

Function Get-rsCloudServersInfo
{
   $catalog = Get-rsServiceCatalog
   $endpoints = ($catalog.access.serviceCatalog | ? name -eq "cloudServersOpenStack").endpoints.publicURL
   foreach( $endpoint in $endpoints )
   {
      $temp = (Invoke-rsRestMethod -Uri $($endpoint,"servers/detail" -join "/") -Method GET -Headers $(Get-rsAuthToken) -ContentType application/json)
      $servers = $servers,$temp
   }
   return ( ($servers.servers | ? { @("Deleted", "Error", "Unknown") -notcontains $_.status} ) )
} 
Function Unlock-Credentials
{
   param(
      [Parameter(Mandatory=$true)]
      [string]$DatabagName
   )
   . (Get-rsSecrets)
   
   $filePath = ("C:\DevOps", $d.mR, "$DatabagName.json" -join "\")
   If ( -not (Test-Path -Path $filePath))
   {
      return $null
   }
   
   $encryptedObjects = [System.IO.File]::ReadAllText($filePath) | ConvertFrom-Json
   
   $credHT = New-Object 'System.Collections.Generic.Dictionary[string,pscredential]'
   if($encryptedObjects -ne $null) {
      foreach ( $Name in ($encryptedObjects | Get-Member -MemberType Properties).Name )
      {
         $item = $encryptedObjects.$Name
         $decryptCert = Get-ChildItem Cert:\LocalMachine\My\ | Where-Object { $_.Thumbprint -eq [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($item.Thumbprint)) }
         If ( -not $decryptCert ) 
         { 
            Write-Host "Certificate with Thumbprint $Thumbprint could not be found. Skipping."
            Continue
         }
         
         try
         {
            
            $key = $decryptCert.PrivateKey.Decrypt([System.Convert]::FromBase64String($item.encrypted_key), $true)
            $secString = ConvertTo-SecureString -String $item.encrypted_data -Key $key
         }
         finally
         {
            if ($key) { [array]::Clear($key, 0, $key.Length) }
         }
         $credHT[$Name] = New-Object pscredential($Name, $secString)
      }
   }
   return $credHT
}
Function Test-rsHash
{
   param (
      [String] $file,
      [String] $hash
   )
   if ( !(Test-Path $hash) ){
      return $false
   }
   if( (Get-FileHash $file).hash -eq (Import-Csv $hash).hash){
      return $true
   }
   if( (Get-FileHash $file).hash -eq (Import-Csv $hash)){
      return $true
   }
   else {
      return $false
   }
}
Function Set-rsHash
{
   param (
      [String] $file,
      [String] $hash
   )
   Set-Content -Path $hash -Value (Get-FileHash -Path $file | ConvertTo-Csv)
}
Function Invoke-DSC
{
    do {
        Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "Installing DSC $("C:\DevOps", $d.mR, "rsPullServer.ps1" -join '\')"
        taskkill /F /IM WmiPrvSE.exe
        try{
            $rstime = Measure-Command {Invoke-Expression $('C:\DevOps', $d.mR, 'rsPullServer.ps1' -join '\')}
        }
        catch {
            Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 1002 -Message "Error in rsPullServer`n$($_.Exception.message)"
        }
    }
    while (!(Test-Path -Path "C:\Windows\System32\Configuration\Current.mof"))
    Write-EventLog -LogName DevOps -Source rsCommon -EntryType Information -EventId 1000 -Message "PullServer DSC installation completed in $($rstime.TotalSeconds) seconds" 
}