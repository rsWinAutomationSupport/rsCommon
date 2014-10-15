if(Test-Path -Path "C:\DevOps\secrets.ps1") {
   . "C:\DevOps\secrets.ps1"
}
if(Test-Path -Path "C:\DevOps\dedicated.csv") {
   $DedicatedData = Import-Csv -Path "C:\DevOps\dedicated.csv"
}
if(Test-Path -Path $($d.wD, $d.mR, 'PullServer.info' -join '\')) {
   . "$($d.wD, $d.mR, 'PullServer.info' -join '\')"
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
               Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "API call Failed `n $($_.ExceptionMessage)"
            }
            else {
               Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "API call Failed `n $($_.ExceptionMessage)"
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
               Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "API call Failed `n $($_.ExceptionMessage)"
            }
            else {
               Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "API call Failed `n $($_.ExceptionMessage)"
               break
            }
         }
      }
      $i++
      if($Data -eq $null) {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Error -EventId 10002 -Message "Failed API call trying again in $timeOuts seconds`n $($_.ExceptionMessage)"
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
Function New-EventLog {
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
   if(isCloud) {
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
   if(isCloud) {
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
      }
      catch {
         Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "Failed to download $url sleeping for $timeOut seconds then trying again. `n $($_.Exception.Message)"
         $i++
         Start-Sleep -Seconds $timeOut
      }
   }
   while (!(Test-Path -Path $path))
   return
}