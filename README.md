rsCommon
========

To use:

Clone to directory<br>
C:\Program Files\WindowsPowerShell\Modules\

```Posh
Import-Module rsCommon
```Posh

Get-Command -Module rsCommon


```PoSh
rsGit rsCommon
{
    name = "rsCommon"
    Source = "https://github.com/rsWinAutomationSupport/rsCommon.git"
    Destination = "C:\Program Files\WindowsPowerShell\Modules\"
    Ensure = "Present"
    Branch = "master"
}
```