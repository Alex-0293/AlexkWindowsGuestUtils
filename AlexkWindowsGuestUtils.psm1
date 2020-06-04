function Set-KeyboardConfig {
    param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "VM name." )]
        [ValidateNotNull()]
        [string] $VMName,
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "VM Credentials." )]
        [System.Management.Automation.PSCredential] $GuestCredentials
    ) 
    $ScriptBlock = {
        $ScriptBlock = {
            Set-ItemProperty -path "HKCU:\Keyboard Layout\Preload" -name "1"               -value "00000409" #Eng
            Set-ItemProperty -path "HKCU:\Keyboard Layout\Preload" -name "2"               -value "00000419" #Ru
            Set-ItemProperty -path "HKCU:\Keyboard Layout\Toggle"  -name "Language Hotkey" -value "2"
        }
        $Res = Invoke-Command -VMName $Using:VMName -ScriptBlock $ScriptBlock -credential $Using:GuestCredentials 
        return $res       
    }
    Add-ToLog -Message "Setting VM [$VMName] keyboard parameters." -logFilePath $ScriptLogFilePath -display -status "Info"
    $res = Invoke-PSScriptBlock -Computer $Computer -Credential $Credentials -ScriptBlock $ScriptBlock -TestComputer -ExportedParameters $PSBoundParameters  
    return $res     
}
function Set-DriveLabel {
    param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "VM name." )]
        [ValidateNotNull()]
        [string] $VMName,
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "VM Credentials." )]
        [System.Management.Automation.PSCredential] $GuestCredentials
    ) 
    $ScriptBlock = {
        $ScriptBlock = {
            Set-Volume -DriveLetter C -NewFileSystemLabel "SYS" -ErrorAction SilentlyContinue
            Set-Volume -DriveLetter D -NewFileSystemLabel "DATA" -ErrorAction SilentlyContinue
        }
        $Res = Invoke-Command -VMName $Using:VMName -ScriptBlock $ScriptBlock -credential $Using:GuestCredentials 
        return $res       
    }
    Add-ToLog -Message "Setting VM [$VMName] volume label changing." -logFilePath $ScriptLogFilePath -display -status "Info"
    $res = Invoke-PSScriptBlock -Computer $Computer -Credential $Credentials -ScriptBlock $ScriptBlock -TestComputer -ExportedParameters $PSBoundParameters  
    return $res     
}
function Set-GuestBGInfo {
    param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "VM name." )]
        [ValidateNotNull()]
        [string] $VMName,
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "VM Credentials." )]
        [System.Management.Automation.PSCredential] $GuestCredentials,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "BGInfo installer URL." )]
        [ValidateNotNull()]
        [string]$BGInfoInstallerURL 
    )
    $ScriptBlock = {
        $ScriptBlock = {
            Param(
                [string] $BGInfoInstallerURL
            )
            $FilePath = "$Env:USERPROFILE\Downloads\$(Split-Path -Path $BGInfoInstallerURL -Leaf)"
            Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
            Invoke-WebRequest -Uri $BGInfoInstallerURL  -OutFile $FilePath
            $BGInfoFolder = "$Env:USERPROFILE\Downloads\BGInfo"
            Remove-Item  $BGInfoFolder -Force -Recurse -ErrorAction SilentlyContinue
            Expand-Archive $FilePath -DestinationPath $BGInfoFolder
            Remove-Item  $FilePath -Force

            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Alex-0293/VMScripts/master/DATA/custom.bgi"  -OutFile "$BGInfoFolder\custom.bgi"
     
            & "$BGInfoFolder\bginfo64.exe" "$BGInfoFolder\custom.bgi" /accepteula /timer:0 /log "$BGInfoFolder\errors.log"  
            $desktopImage = "C:\Windows\BGInfo.bmp"
            
            Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name TileWallpaper  -value "0"           -Force
            Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name WallpaperStyle -value "10"           -Force
            Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name Wallpaper      -value $desktopImage -Force
            <#
                Two registry values are set in the Control Panel\Desktop key.
                
                TileWallpaper
                0: The wallpaper picture should not be tiled 
                1: The wallpaper picture should be tiled 
                
                WallpaperStyle
                0:  The image is centered if TileWallpaper=0 or tiled if TileWallpaper=1
                2:  The image is stretched to fill the screen
                6:  The image is resized to fit the screen while maintaining the aspect 
                    ratio. (Windows 7 and later)
                10: The image is resized and cropped to fill the screen while 
                    maintaining the aspect ratio. (Windows 7 and later)
            #>

        }
        Invoke-Command -VMName $Using:VMName -ScriptBlock $ScriptBlock -credential $Using:GuestCredentials -ArgumentList $Using:BGInfoInstallerURL  
    }
    
    Add-ToLog -Message "Setting VM [$VMName] wallpaper." -logFilePath $ScriptLogFilePath -display -status "Info"
    $res = Invoke-PSScriptBlock -Computer $Computer -Credential $Credentials -ScriptBlock $ScriptBlock -TestComputer -ExportedParameters $PSBoundParameters  
}
function Start-WindowsInitialSetup {
    param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "VM name." )]
        [ValidateNotNull()]
        [string] $VMName,
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "VM Credentials." )]
        [System.Management.Automation.PSCredential] $GuestCredentials,
        [Parameter(Mandatory = $False, Position = 2, HelpMessage = "Preset name." )]
        [ValidateNotNull()]
        [string] $Preset
    )
    # https://github.com/Disassembler0/Win10-Initial-Setup-Script
    # https://github.com/Alex-0293/Win10-Initial-Setup-Script
    $ScriptBlock = {
        $ScriptBlock = {
            Param(
                [string] $Preset
            )
            $WinSettings = "$Env:USERPROFILE\Downloads\WinSettings"
            if (Test-Path $WinSettings) {
                Remove-Item -Path $WinSettings -Recurse -Force
            }
            New-Item -Path $WinSettings -ItemType Directory -Force

            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Alex-0293/Win10-Initial-Setup-Script/master/Win10.ps1"  -OutFile "$WinSettings\Win10.ps1"  
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Alex-0293/Win10-Initial-Setup-Script/master/Win10.psm1" -OutFile "$WinSettings\Win10.psm1" 

            if ($Preset) {                
                Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Alex-0293/Win10-Initial-Setup-Script/master/$Preset"  -OutFile "$WinSettings\$Preset"
            }
            Else {
                Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Alex-0293/Win10-Initial-Setup-Script/master/My.preset"  -OutFile "$WinSettings\My.preset"
                $Preset = "My.preset"
            }       

            Set-Location -path $WinSettings
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File Win10.ps1 -include Win10.psm1 -preset $Preset -log output.log
        }
        
        Invoke-Command -VMName $Using:VMName -ScriptBlock $ScriptBlock -credential $Using:GuestCredentials -ArgumentList $Using:Preset 
    }
    
    Add-ToLog -Message "VM [$VMName] windows initial setup." -logFilePath $ScriptLogFilePath -display -status "Info"
    $res = Invoke-PSScriptBlock -Computer $Computer -Credential $Credentials -ScriptBlock $ScriptBlock -TestComputer -ExportedParameters $PSBoundParameters  
}
function Get-GuestWindowsOSVersion {
    param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "VM name." )]
        [ValidateNotNull()]
        [string] $VMName,
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "VM Credentials." )]
        [System.Management.Automation.PSCredential] $GuestCredentials
    ) 
    $ScriptBlock = {
        $ScriptBlock = {
            $Res = (Get-WmiObject Win32_OperatingSystem).Caption
            return $Res
        }        
        $Res = Invoke-Command -VMName $Using:VMName -ScriptBlock $ScriptBlock -credential $Using:GuestCredentials 
        return $res       
    }
    Add-ToLog -Message "Getting VM [$VMName] windows OS version." -logFilePath $ScriptLogFilePath -display -status "Info"
    $res = Invoke-PSScriptBlock -Computer $Computer -Credential $Credentials -ScriptBlock $ScriptBlock -TestComputer -ExportedParameters $PSBoundParameters  
    return $res    
    
}
function Rename-WindowsGuest {
    param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "VM name." )]
        [ValidateNotNull()]
        [string] $VMName,
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "VM Credentials." )]
        [System.Management.Automation.PSCredential] $GuestCredentials,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "New VM OS host name." )]
        [ValidateNotNull()]
        [string] $NewName,
        [Parameter(Mandatory = $false, Position = 3, HelpMessage = "New VM OS host description." )]
        [string] $Description
    ) 
    ([SecureString]$SecurePassword, $UserName, $NewName, $Descr)
    $ScriptBlock = {
        $ScriptBlock = {
            Param(
                [string] $NewName,
                [string] $Description,
                [System.Management.Automation.PSCredential] $Credentials
            )
            $WS = Get-WmiObject Win32_ComputerSystem -ComputerName $env:computername
            $WS.Rename($NewName , $Credentials.GetNetworkCredential().Password, $Credentials.Username) | Out-Null
            $OSWMI = Get-WmiObject -class Win32_OperatingSystem | Out-Null
            $OSWMI.Description = $Description
            $OSWMI.put() | Out-Null
        }
        Invoke-Command -VMName $Using:VMName -ScriptBlock $ScriptBlock -credential $Using:GuestCredentials -ArgumentList $Using:NewName, $Using:Description, $Using:GuestCredentials
    }    
    Add-ToLog -Message "Renaming windows VM [$VMName] OS to [$NewName]." -logFilePath $ScriptLogFilePath -display -status "Info"
    Invoke-PSScriptBlock -Computer $Computer -Credential $Credentials -ScriptBlock $ScriptBlock -TestComputer -ExportedParameters $PSBoundParameters   
}
function Enable-RDPAccess {
    param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "VM name." )]
        [ValidateNotNull()]
        [string] $VMName,
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "VM Credentials." )]
        [System.Management.Automation.PSCredential] $GuestCredentials
    ) 
    
    $ScriptBlock = { 
        $ScriptBlock = {   
            Write-Host "    - Enable RDP access. " -ForegroundColor Green    
            try {
                $ts = Get-WmiObject Win32_TerminalServiceSetting -Namespace ROOT\CIMV2\TerminalServices
                $ts.SetAllowTSConnections(1, 1) | Out-Null
            }
            catch { 
                Write-Host $_
                Write-Host "      Error enabling RDP access." -ForegroundColor Red 
            }
            # Add firewall rule
            Write-Host "    - Add firewall rule ->TCP389 " -ForegroundColor Green
            try {
                $InstanceID = (Get-NetFirewallPortFilter | Where-Object { ($_.localport -eq "3389") -and ($_.Protocol -eq "TCP") } )[0].InstanceID
                $Rule = Get-NetFirewallRule | Where-Object { $_.InstanceID -eq $InstanceID }
                Set-NetFirewallRule -Name $Rule.Name -Enabled True            
            }
            catch {}
            # Setting the NLA information to Enabled
            Write-Host "    - Enable network level auth." -ForegroundColor Green
            try {
                (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices  -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1) | Out-Null
            }
            Catch { 
                Write-Host $_
                Write-Host "      Error enabling NLA." -ForegroundColor Red 
            }   
        }
        $Res = Invoke-Command -VMName $Using:VMName -ScriptBlock $ScriptBlock -credential $Using:GuestCredentials 
        return $res     
    }    

    Add-ToLog -Message "Enabling RDP access on VM [$VMName]." -logFilePath $ScriptLogFilePath -display -status "Info"
    $res = Invoke-PSScriptBlock -Computer $Computer -Credential $Credentials -ScriptBlock $ScriptBlock -TestComputer -ExportedParameters $PSBoundParameters  

}

Export-ModuleMember -Function Set-KeyboardConfig, Set-DriveLabel, Set-GuestBGInfo, Start-WindowsInitialSetup, Get-GuestCredentials, Get-GuestWindowsOSVersion, Rename-WindowsGuest, Enable-RDPAccess