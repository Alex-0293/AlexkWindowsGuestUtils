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
    Add-ToLog -Message "Setting VM [$VMName] guest keyboard parameters." -logFilePath $ScriptLogFilePath -display -status "Info"
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
    Add-ToLog -Message "Setting VM [$VMName] guest volume label changing." -logFilePath $ScriptLogFilePath -display -status "Info"
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
        [string]$BGInfoInstallerURL,
        [Parameter(Mandatory = $true, Position = 3, HelpMessage = "BGInfo installer setting URL." )]
        [ValidateNotNull()]
        [string]$BGInfoInstallerSettingsURL  
    )
    $ScriptBlock = {
        $ScriptBlock = {
            Param(
                [string] $BGInfoInstallerURL,
                [string] $BGInfoInstallerSettingsURL
            )
            #https://docs.microsoft.com/en-us/sysinternals/downloads/bginfo
            $FilePath = "$Env:USERPROFILE\Downloads\$(Split-Path -Path $BGInfoInstallerURL -Leaf)"
            Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
            Invoke-WebRequest -Uri $BGInfoInstallerURL  -OutFile $FilePath
            $BGInfoFolder = "$Env:USERPROFILE\Downloads\BGInfo"
            Remove-Item  $BGInfoFolder -Force -Recurse -ErrorAction SilentlyContinue
            Expand-Archive $FilePath -DestinationPath $BGInfoFolder
            Remove-Item  $FilePath -Force

            Invoke-WebRequest -Uri $BGInfoInstallerSettingsURL -OutFile "$BGInfoFolder\custom.bgi"
     
            & "$BGInfoFolder\bginfo64.exe" "$BGInfoFolder\custom.bgi" /accepteula /timer:0 /log "$BGInfoFolder\errors.log"  
            $desktopImage = "C:\Windows\BGInfo.bmp"
            
            Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name TileWallpaper  -value "0"           -Force
            Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name WallpaperStyle -value "10"          -Force
            Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name Wallpaper      -value $desktopImage -Force

            $WshShell            = New-Object -comObject WScript.Shell
            
            $Shortcut                  = $WshShell.CreateShortcut("$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\StartUp\BGInfo.lnk")
            $Shortcut.TargetPath       = "$BGInfoFolder\bginfo64.exe"
            $Shortcut.Arguments        = "/iq `"custom.bgi`" /accepteula /timer:0"            
            $Shortcut.WorkingDirectory = $BGInfoFolder
            $Shortcut.Save()
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
        Invoke-Command -VMName $Using:VMName -ScriptBlock $ScriptBlock -credential $Using:GuestCredentials -ArgumentList $Using:BGInfoInstallerURL, $Using:BGInfoInstallerSettingsURL  
    }
    
    Add-ToLog -Message "Setting VM [$VMName] guest wallpaper." -logFilePath $ScriptLogFilePath -display -status "Info"
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
            Remove-Item -path "$Env:USERPROFILE\Desktop\*.*" -Force -ErrorAction SilentlyContinue 
        }
        
        Invoke-Command -VMName $Using:VMName -ScriptBlock $ScriptBlock -credential $Using:GuestCredentials -ArgumentList $Using:Preset 
    }
    
    Add-ToLog -Message "Setting VM [$VMName] guest windows initial parameters with preset [$Preset]." -logFilePath $ScriptLogFilePath -display -status "Info"
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
    Add-ToLog -Message "Getting VM [$VMName] guest windows OS version." -logFilePath $ScriptLogFilePath -display -status "Info"
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
    Add-ToLog -Message "Renaming VM [$VMName] windows guest OS to [$NewName]." -logFilePath $ScriptLogFilePath -display -status "Info"
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

    Add-ToLog -Message "Enabling RDP access on VM [$VMName] windows guest." -logFilePath $ScriptLogFilePath -display -status "Info"
    $res = Invoke-PSScriptBlock -Computer $Computer -Credential $Credentials -ScriptBlock $ScriptBlock -TestComputer -ExportedParameters $PSBoundParameters  

}
function Set-WinTaskBand {
    param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "VM name." )]
        [ValidateNotNull()]
        [string] $VMName,
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "VM Credentials." )]
        [System.Management.Automation.PSCredential] $GuestCredentials,
        [Parameter(Mandatory  = $true, Position = 2, HelpMessage = "Taskband URL." )]
        [ValidateNotNull()]
        [string] $TaskbandURL
    ) 
    $ScriptBlock = {
        $ScriptBlock = {
            param(
                [string] $TaskbandURL
            )
            $Folder = "$Env:USERPROFILE\Downloads\TaskBand"
            Remove-Item -path $Folder -Recurse -force -ErrorAction SilentlyContinue
            New-Item -Path $Folder -ItemType Directory -Force | Out-Null
            $FilePath = "$Folder\taskband.zip"

            Invoke-WebRequest -Uri $TaskbandURL  -OutFile $FilePath
            Expand-Archive $FilePath -DestinationPath $Folder
            Remove-Item -path $FilePath -force
  
            Start-Process $env:windir\System32\reg.exe -ArgumentList "import $Folder\TaskbandCU.reg" -WindowStyle Hidden
            Copy-Item -Path "$Folder\Quick launch\*" -Destination $env:UserProfile'\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch' -Recurse -Force -ErrorAction SilentlyContinue
            Stop-Process -ProcessName explorer -Force -ErrorAction SilentlyContinue
        }
        Invoke-Command -VMName $Using:VMName  -credential $Using:GuestCredentials -ScriptBlock $ScriptBlock -ArgumentList $Using:TaskbandURL    
    }
    Add-ToLog -Message "Setting VM [$VMName] guest windows task band." -logFilePath $ScriptLogFilePath -display -status "Info"
    Invoke-PSScriptBlock -Computer $Computer -Credential $Credentials -ScriptBlock $ScriptBlock -TestComputer -ExportedParameters $PSBoundParameters  
}

function Install-GuestWindowsFeature {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 07.05.2020
        .VER 1   
    .DESCRIPTION
     Function to import or create new VM with custom parameters.
    .EXAMPLE
    Create new VM:
        Add-NewCustomVM  -Computer "Host1" -Credentials $Credentials -NewVMName "Test" -Mode "New" -VMConfig $VMConfig -NETConfig $NETConfig -StartupConfig $StartupConfig -ISOFile $ISOFile -ImportPath $ImportPath -RDPShortcutsFolderPath $RDPShortcutsFolderPath -StartVM -AddIndex -StartRDPConsole

    Import exported VM:
        Add-NewCustomVM  -Computer "Host1" -Credentials $Credentials -NewVMName "Test" -Mode "Import" -ImportPath $ImportPath -VMTemplatePath $VMTemplatePath -RDPShortcutsFolderPath $RDPShortcutsFolderPath -StartVM
    #> 
    param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "VM name." )]
        [ValidateNotNull()]
        [string] $VMName,
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "VM Credentials." )]
        [System.Management.Automation.PSCredential] $GuestCredentials,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "Argument list." )]
        [ValidateNotNull()]
        [array] $CommandList
    ) 
    $ScriptBlock = {
        $ScriptBlock = {
            param(
                [array] $CommandList
            )
           

            Invoke-WebRequest -Uri $TaskbandURL  -OutFile $FilePath
            Expand-Archive $FilePath -DestinationPath $Folder
            Remove-Item -path $FilePath -force  
            
        }
        Invoke-Command -VMName $Using:VMName  -credential $Using:GuestCredentials -ScriptBlock $ScriptBlock -ArgumentList $Using:CommandList    
    }
    Add-ToLog -Message "Setting VM [$VMName] guest windows features" -logFilePath $ScriptLogFilePath -display -status "Info"
    Invoke-PSScriptBlock -Computer $Computer -Credential $Credentials -ScriptBlock $ScriptBlock -TestComputer -ExportedParameters $PSBoundParameters 
}

function Set-GuestWindowsNetworkParameters {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 27.05.2020
        .VER 1   
    .DESCRIPTION
     Function to set ip parameters in the VM guest windows OS.
    .EXAMPLE
   
        Set-GuestWindowsNetworkParameters -VMName $VMName -GuestCredentials $GuestCredentials -IPAddress $IPAddress -NetMask $NetMask  -DefaultGateway $DefaultGateway -DNSServers $DNSServers -NICNumber $NICNumber
    #>  
    [CmdletBinding()]   
    param(
        [Parameter(Mandatory = $true,  Position = 0, HelpMessage = "VM name." )]
        [ValidateNotNull()]
        [string] $VMName,
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "VM Credentials." )]
        [System.Management.Automation.PSCredential] $GuestCredentials,
        [Parameter(Mandatory = $true,  Position = 2, HelpMessage = "IP address." )]
        [ValidateNotNull()]
        [string] $IPAddress,
        [Parameter(Mandatory = $true,  Position = 3, HelpMessage = "Network mask." )]
        [ValidateNotNull()]
        [string] $NetMask,
        [Parameter(Mandatory = $true,  Position = 4, HelpMessage = "Default gateway." )]
        [ValidateNotNull()]
        [string] $DefaultGateway,
        [Parameter(Mandatory = $false, Position = 5, HelpMessage = "DNS servers list." )]
        [ValidateNotNull()]
        [string] $DNSServers,
        [Parameter(Mandatory = $true,  Position = 6, HelpMessage = "NIC number." )]
        [ValidateNotNull()]
        [int] $NICNumber
    ) 
    $ScriptBlock = {
        $ScriptBlock = {
            param(
                [Parameter(Mandatory = $true, Position = 1, HelpMessage = "IP address." )]
                [ValidateNotNull()]
                [string] $IPAddress,
                [Parameter(Mandatory = $true, Position = 2, HelpMessage = "Network mask." )]
                [ValidateNotNull()]
                [string] $NetMask,
                [Parameter(Mandatory = $true, Position = 3, HelpMessage = "Default gateway." )]
                [ValidateNotNull()]
                [string] $DefaultGateway,
                [Parameter(Mandatory = $false, Position = 4, HelpMessage = "DNS servers list." )]
                [ValidateNotNull()]
                [string] $DNSServers,
                [Parameter(Mandatory = $true, Position = 5, HelpMessage = "NIC number." )]
                [ValidateNotNull()]
                [int] $NICNumber
            ) 
            
            $NICs = Get-WMIObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Select-Object -first $NICNumber
            $NIC  = $NICs | Select-Object -Last 1
            Write-Host "Selected Network adapter: $($NIC.Name)"

            $NIC.EnableStatic($IPAddress , @($NetMask)) | out-null
            $NIC.SetGateways($DefaultGateway) | Out-Null
            if ($DNSServers) {
                $NIC.SetDNSServerSearchOrder($DNSServers) | Out-Null
            }
            $NIC.SetDynamicDNSRegistration("False") | Out-Null
        }
        Invoke-Command -VMName $Using:VMName  -credential $Using:GuestCredentials -ScriptBlock $ScriptBlock -ArgumentList $Using:IPAddress, $Using:NetMask, $Using:DefaultGateway, $Using:DNSServers, $Using:NICNumber    
    }
    Add-ToLog -Message "Setting VM [$VMName] guest windows ip parameters." -logFilePath $ScriptLogFilePath -display -status "Info"
    Invoke-PSScriptBlock -Computer $Computer -Credential $Credentials -ScriptBlock $ScriptBlock -TestComputer -ExportedParameters $PSBoundParameters 
}

Export-ModuleMember -Function Set-KeyboardConfig, Set-DriveLabel, Set-GuestBGInfo, Start-WindowsInitialSetup, Get-GuestCredentials, Get-GuestWindowsOSVersion, Rename-WindowsGuest, Enable-RDPAccess, Set-WinTaskBand, Install-GuestWindowsFeature, Set-GuestWindowsNetworkParameters