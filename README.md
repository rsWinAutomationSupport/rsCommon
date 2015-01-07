rsCommon
========

To use:

Clone to directory<br>
C:\Program Files\WindowsPowerShell\Modules\

Import-Module rsCommon

Get-Command -Module rsCommon


```Posh
rsGit rsCommon
{
    name = "rsCommon"
    Source = "https://github.com/rsWinAutomationSupport/rsCommon.git"
    Destination = "C:\Program Files\WindowsPowerShell\Modules\"
    Ensure = "Present"
    Branch = "master"
}
```