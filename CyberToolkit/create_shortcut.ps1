$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut("$env:USERPROFILE\Desktop\GhostStrike.lnk")
$sc.TargetPath = "$PSScriptRoot\GhostStrike.vbs"
$sc.WorkingDirectory = "$PSScriptRoot"
$sc.Description = "GhostStrike - Penetration Testing Toolkit"
$sc.IconLocation = "shell32.dll,13"
$sc.Save()
Write-Host "Desktop shortcut created!"
