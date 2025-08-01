$Action = New-ScheduledTaskAction -Execute `
"pwsh –Noprofile -WindowStyle Hidden -ExecutionPolicy Bypass -File $home\script.ps1"
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
-RepetitionInterval (New-TimeSpan -Minutes 15)
$Principal = New-ScheduledTaskPrincipal -UserId pagr\administrator
$Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal
Register-ScheduledTask -TaskName "Test4" -InputObject $Task -Force