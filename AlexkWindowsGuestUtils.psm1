"DomainController", "Workstation", "Server", "Gateway"
$Global:IPRoles = [PSCustomObject]@{
    DomainController = 1
    Workstation      = 40..100
    Server           = 2..10
    Gateway          = 254
}

$Global:NetworkConfigType = [PSCustomObject]@{
    Static = "Static"
    DHCP   = "DHCP"
}
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

    $ScriptBlock = {
        $ScriptBlock = {
            Param(
                [string] $NewName,
                [string] $Description,
                [System.Management.Automation.PSCredential] $Credentials
            )
            $WS = Get-WmiObject Win32_ComputerSystem -ComputerName $env:computername
            $WS.Rename($NewName , $Credentials.GetNetworkCredential().Password, $Credentials.Username) | Out-Null
            $OSWMI = Get-WmiObject -class Win32_OperatingSystem 
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

function Invoke-GuestWindowsCommand {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 09.06.2020
        .VER 1   
    .DESCRIPTION
     Function run command on the guest Windows system.
    .EXAMPLE
        Invoke-GuestWindowsCommand  -VMName $VMName -GuestCredentials $GuestCredentials -CommandList $CommandList
    #> 
    param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "VM name." )]
        [ValidateNotNull()]
        [string] $VMName,
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "VM Credentials." )]
        [System.Management.Automation.PSCredential] $GuestCredentials,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "Command list." )]
        [ValidateNotNull()]
        [string] $Command,
        [Parameter(Mandatory = $false, Position = 3, HelpMessage = "Argument list." )]
        [ValidateNotNull()]
        [HashTable] $ArgumentList
    ) 
    $ScriptBlock = {
        $ScriptBlock = {
            param(
                [string] $Command,
                [HashTable] $ArgumentList
            )
           
            #Write-Host "Run: $Command"            
            $Scriptblock = [scriptblock]::Create($Command)
            $Res = Invoke-Command -ScriptBlock $Scriptblock
            return $Res
        }
        $Res = Invoke-Command -VMName $Using:VMName  -credential $Using:GuestCredentials -ScriptBlock $ScriptBlock -ArgumentList $Using:Command, $Using:ArgumentList 
        Return $res  
    }
    Add-ToLog -Message "Invoking VM [$VMName] guest command." -logFilePath $ScriptLogFilePath -display -status "Info"
    $Res = Invoke-PSScriptBlock -Computer $Computer -Credential $Credentials -ScriptBlock $ScriptBlock -TestComputer -ExportedParameters $PSBoundParameters 
    Return $res
}

function Invoke-GuestWindowsCommandGroup {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 12.06.2020
        .VER 1   
    .DESCRIPTION
     Function run group of command on the guest Windows system.
    .EXAMPLE
        Invoke-GuestWindowsCommandGroup  -Computer $Computer -Credentials $Credentials -VMName $VMName -GuestCredentials $GuestCredentials -CommandGroupName $CommandGroupName -BGInfoInstallerURL $BGInfoInstallerURL -TaskbandURL $TaskbandURL -GuestOSName $GuestOSName -NewName $NewName -NetworkHost $NetworkHost -UsersCount $UsersCount
    #> 
    param(
        [Parameter( Mandatory = $False, Position = 0, HelpMessage = "Remote computer name.")]   
        [string] $Computer,
        [Parameter( Mandatory = $False, Position = 1, HelpMessage = "Remote credentials.")]
        [System.Management.Automation.PSCredential]  $Credentials,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "VM name." )]
        [ValidateNotNull()]
        [string] $VMName,
        [Parameter( Mandatory = $True, Position = 3, HelpMessage = "VM Credentials." )]
        [System.Management.Automation.PSCredential] $GuestCredentials,
        [Parameter(Mandatory = $true, Position = 4, HelpMessage = "Command group name." )]
        [ValidateNotNull()]
        [string] $CommandGroupName,
        [Parameter(Mandatory = $True, Position = 5, HelpMessage = "BGInfo installer URL." )]
        [ValidateNotNull()]
        [string] $BGInfoInstallerURL,
        [Parameter(Mandatory = $True, Position = 6, HelpMessage = "BGInfo settings URL." )]
        [ValidateNotNull()]
        [string] $BGInfoInstallerSettingsURL,
        [Parameter(Mandatory = $True, Position = 7, HelpMessage = "Taskband URL." )]
        [ValidateNotNull()]
        [string] $TaskbandURL,
        [Parameter(Mandatory = $True, Position = 8, HelpMessage = "Guest OS name." )]
        [ValidateNotNull()]
        [string] $GuestOSName,    
        [Parameter(Mandatory = $True, Position = 9, HelpMessage = "Network host parameters." )]
        [ValidateNotNull()]
        $NetworkHost,
        [Parameter(Mandatory = $True, Position = 10, HelpMessage = "Users count to create." )]
        [ValidateNotNull()]
        [int] $UsersCount
    ) 
      
    Add-ToLog -Message "Running command group [$CommandGroupName] on VM [$($VMName)] guest OS [$VMName]." -logFilePath $ScriptLogFilePath -Display -Status "Info"
    switch ($CommandGroupName) {
        "Install updates" { 

        }
        "Install remoting" { 
            Enable-RDPAccess $VMName $GuestCredentials
        }
        "Configure" { 
            Set-KeyboardConfig        -VMName $VMName -GuestCredentials $GuestCredentials
            Set-DriveLabel            -VMName $VMName -GuestCredentials $GuestCredentials
            Set-GuestBGInfo           -VMName $VMName -GuestCredentials $GuestCredentials -BGInfoInstallerURL $Global:BGInfoInstallerURL -BGInfoInstallerSettingsURL $Global:BGInfoInstallerSettingsURL
            Set-WinTaskBand           -VMName $VMName -GuestCredentials $GuestCredentials -TaskbandURL $Global:TaskbandURL                
            switch -Wildcard ($GuestOSName.ToUpper()) {
                "*SERVER*2016*" { $Preset = "Win2016.preset" }
                "*10*" { $Preset = "Win10.preset" }
                Default { }
            }
            Start-WindowsInitialSetup -VMName $VMName -GuestCredentials $GuestCredentials -Preset $Preset 
            
            $RestartRequired = $True                   
        }
        "Rename" { 
            $HostName = Get-HostNameFromSeries -Computer $Computer -Credentials $Credentials -HostNameSeries $NetworkHost.HostNameSeries
            Rename-WindowsGuest -VMName $VMName -GuestCredentials $GuestCredentials -NewName $HostName      
            $RestartRequired = $True
        }
        "Set network" {
            Foreach ($Network in $NetworkHost.NETConfig) { 
                if ($Network.Switch.Config -eq $Global:NetworkConfigType.Static ) {
                    Set-GuestWindowsNetworkParameters -Computer $Computer -Credentials $Credentials -Network $Network -VMName $VMName -GuestCredentials $GuestCredentials
                }
            }                
        }
        "Install AD" {
            #https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-
                        
            $Command = { 
                Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools 
            }
            $Res = Invoke-GuestWindowsCommand -VMName $VMName -GuestCredentials $GuestCredentials -Command $Command
            if ([bool]$Res.Success) { 
                $Command = {
                    Import-Module ADDSDeployment
                    $SafeModeAdministratorPassword = ConvertTo-SecureString $ArgumentList.SafeModeAdministratorPassword -AsPlainText -Force
                    Install-ADDSForest -DomainName "$($ArgumentList.DomainName)" -InstallDns -SafeModeAdministratorPassword $SafeModeAdministratorPassword -Force
                }    
                $ArgumentList = @{DomainName = $DomainName; SafeModeAdministratorPassword = $SafeModeAdministratorPassword }                
                $Res = Invoke-GuestWindowsCommand -VMName $VMName -GuestCredentials $GuestCredentials -Command $Command -ArgumentList $ArgumentList
                Start-Sleep -Seconds 20
                if ([bool]$Res.Status) {
                    Add-ToLog -Message "Successfully installed AD [$($Global:DomainName )] on [$HostName ]." -logFilePath $ScriptLogFilePath -display -status "Info"
                }
                Else {
                    throw "Error while installing [Install-ADDSForest -DomainName $($ArgumentList.DomainName) -InstallDns -SafeModeAdministratorPassword $SafeModeAdministratorPassword -Force] `n $Res"
                }
            }
            else {
                throw "Error while installing [Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools] `n $Res"
            }
            
        }
        "Create AD test LDAP objects" {
            $Command = {                
                Function Add-ADOrganizationalUnit {
                    param(
                        [string] $OuName,
                        [string] $ParentPath
                    )
    
                    $Ou = Get-ADOrganizationalUnit -Filter 'name -eq $OuName' -SearchBase $ParentPath
                    if ( $null -eq $Ou ) {
                        Write-Host  "Adding organization unit [$OuName] in [$ParentPath]."  -ForegroundColor Green 
                        New-ADOrganizationalUnit -name $OuName -Path $ParentPath
                        $Ou = Get-ADOrganizationalUnit -Filter 'name -eq $OuName' -SearchBase $ParentPath       
                    }
                    Else {        
                        Write-Host  "Organization unit [$OuName] already exist in [$ParentPath]!"  -ForegroundColor Red
                    }
                    return $Ou.DistinguishedName
                }
                Function New-User {
    
                    $Sex = "Male", "Female" | Get-Random

                    if ($Sex -eq "Male") {
                        $GivenName = $Global:MaleNames |  Get-Random
                        if ($Global:UniqueNames) {
                            $Global:MaleNames = $Global:MaleNames | Where-Object { $_ -ne $GivenName }
                        }
                    }
                    Else {
                        $GivenName = $Global:FemaleNames | Get-Random
                        if ($Global:UniqueNames) {
                            $Global:FemaleNames = $Global:FemaleNames | Where-Object { $_ -ne $GivenName }
                        }
                    }
    
                    $Surname = $Global:Surname1 | Get-Random
                    if ($Global:UniqueNames) {
                        $Global:Surname1 = $Global:Surname1 | Where-Object { $_ -ne $Surname }
                    }

    
                    if ($Global:DepartmentsWithLimits) {
                        $Global:Limits = @()
                        foreach ($Item in $Global:DepartmentsWithLimits.keys) {
                            $Departments = [PSCustomObject]@{
                                Name    = $Item
                                Percent = $Global:DepartmentsWithLimits.$Item
                                Max     = [math]::Round($Global:UsersCount / 100 * $Global:DepartmentsWithLimits.$Item, 0)
                                Count   = ($Global:users | Where-Object { $_.Department -eq $Item }).count
                            }
                            $Global:Limits += $Departments
                        }
        
                        do {
                            $Department = $Global:Departments | Get-Random
                            $DepartmentLimit = $Global:Limits | Where-Object { $_.Name -eq $Department }
                        } until ($DepartmentLimit.Count -lt $DepartmentLimit.Max)
                        $DepartmentLimit.Count ++    
                    }
                    Else {
                        $Department = $Global:Departments | Get-Random 
                    }    
                    $Initials = ($Global:Surname | Get-Random ).SubString(0, 1)
                    $Name = "$GivenName $Initials. $Surname"
                    $DisplayName = "$GivenName $Initials. $Surname"
                    $SamAccountName = "$GivenName.$Surname"
                    $UserPassword = ConvertTo-SecureString $Global:DefaultUserPassword -AsPlainText -Force
                    $Enabled = $true
                    $ChangePasswordAtLogon = $false
                    $Company = $Global:CompanyName
                    $AllowReversiblePasswordEncryption = $False
                    $Division = $Global:OfficeLocations | Get-Random
                    $OfficePhone = (1..3 | ForEach-Object { "1", "2", "3", "4", "5", "6", "7", "8", "9", "0" | Get-Random }) -join ""
                    $MobilePhone = "+$(Get-Random -Maximum 99) ($((1..3 | ForEach-Object { "1", "2", "3", "4", "5", "6", "7", "8", "9", "0" | Get-Random }) -join '')) $((1..7 | ForEach-Object { "1", "2", "3", "4", "5", "6", "7", "8", "9", "0" | Get-Random }) -join '')"
                    $Title = $Global:Title | Get-Random
                    $Email = "$SamAccountName@$($Global:CompanyName).com"

                    $User = [PSCustomObject]@{
                        Sex                               = $Sex
                        Name                              = $Name
                        GivenName                         = $GivenName
                        Surname                           = $Surname
                        Department                        = $Department
                        EmployeeID                        = $Global:EmployeeNumber
                        DisplayName                       = $DisplayName
                        SamAccountName                    = $SamAccountName
                        AccountPassword                   = $UserPassword
                        Enabled                           = $Enabled
                        ChangePasswordAtLogon             = $ChangePasswordAtLogon
                        Company                           = $Company
                        AllowReversiblePasswordEncryption = $AllowReversiblePasswordEncryption
                        Initials                          = $Initials
                        Division                          = $Division
                        OfficePhone                       = $OfficePhone
                        MobilePhone                       = $MobilePhone
                        Title                             = $Title 
                        Email                             = $Email 
                    }
                    $Global:EmployeeNumber ++
                    Return $User
                }             
                $Global:UsersCount = $ArgumentList.UsersCount   
                $Global:UniqueNames = $False
                [array] $Global:MaleNames = "James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph", "Thomas", "Charles", "Christopher", "Daniel", "Matthew", "Anthony", "Donald", "Mark", "Paul", "Steven", "Andrew", "Kenneth"
                [array] $Global:FemaleNames = "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara", "Susan", "Jessica", "Sarah", "Karen", "Nancy", "Margaret", "Lisa", "Betty", "Dorothy", "Sandra", "Ashley", "Kimberly", "Donna", "Emily"
                [array] $Global:Surname = "Smith", "Johnson", "Williams", "Brown", "Jones", "Miller", "Davis", "Garcia", "Rodriguez", "Wilson", "Martinez", "Anderson", "Taylor", "Thomas", "Hernandez", "Moore", "Martin", "Jackson", "Thompson", "White"
                [string]  $Global:CompanyName = "HomeCorp"         
                [array]   $Global:OfficeLocations = "Moscow", "London"         
                [array]   $Global:Departments = "IT", "ACCOUNTING", "PRODUCTION"  
                [string] $Global:DefaultUserPassword = "ju632rf%g"         
                [array]  $Global:DepartmentsWithLimits = @{"IT" = 10 }, @{"PRODUCTION" = 60 }, @{"ACCOUNTING" = 30 }         # Limit number of department employee in percents. Overall 100%.
                [array] $Global:Title = "Specialist", "Manager", "Administrator", "Assistant"
                $res = Import-Module ActiveDirectory -PassThru -Force
                if ($res) {  
                    $Global:ParentLevel ++    
                    $ScriptLogFilePath = "C:\AdFill.log"
                    Write-Host  "Generating users." -ForegroundColor Green
                    $Global:Surname1 = $Global:Surname
                    [int] $Global:EmployeeNumber = 1
                    $Global:users = @()

                    for ($i = 1; $i -le $Global:UsersCount; $i++) {
                        $Global:users += New-User
                    }
                    #$Global:users  | Select-Object EmployeeID, Sex, DisplayName, Department, SamAccountName, Company, Office, OfficePhone, MobilePhone  | Format-Table -AutoSize
                    #$Global:Limits | Format-Table -AutoSize
                    Write-Host  "Users generated." -ForegroundColor Green

                    $ORGRootPath = (Get-ADDomain).DistinguishedName    
                    Write-Host  "Generating organization units in [$ORGRootPath]."  -ForegroundColor Green  
                    $Global:ParentLevel ++
                    $OuCompany = Add-ADOrganizationalUnit $CompanyName $ORGRootPath
                    $OuGROUPS = Add-ADOrganizationalUnit "GROUPS" $OuCompany
                    $OuACL = Add-ADOrganizationalUnit "ACL" $OuGROUPS
                    $Ou = Add-ADOrganizationalUnit "DISABLED" $OuACL 
                    $OuAPP = Add-ADOrganizationalUnit "APP"  $OuGROUPS
                    $Ou = Add-ADOrganizationalUnit "DISABLED"  $OuAPP
                    $OuDST = Add-ADOrganizationalUnit "DST"  $OuGROUPS
                    $Ou = Add-ADOrganizationalUnit "DISABLED"  $OuDST
                    $OuSHD = Add-ADOrganizationalUnit "SHD"  $OuGROUPS
                    $Ou = Add-ADOrganizationalUnit "DISABLED"  $OuSHD
                    $OuDEVICES = Add-ADOrganizationalUnit "DEVICES"  $OuCompany
                    $OuDC = Add-ADOrganizationalUnit "DC"  $OuDEVICES
                    ForEach ($Item in $Global:OfficeLocations) {
                        $OuLoc = Add-ADOrganizationalUnit $Item  $OuDC
                        $Ou = Add-ADOrganizationalUnit "DISABLED"  $OuLoc
                    }
                    $OuSERVERS = Add-ADOrganizationalUnit "SERVERS"  $OuDEVICES
                    ForEach ($Item in $Global:OfficeLocations) {
                        $OuLoc = Add-ADOrganizationalUnit $Item  $OuSERVERS
                        $Ou = Add-ADOrganizationalUnit "DISABLED"  $OuLoc
                    }
                    $OuWORKSTATIONS = Add-ADOrganizationalUnit "WORKSTATIONS"  $OuDEVICES
                    ForEach ($Item in $Global:OfficeLocations) {
                        $OuLoc = Add-ADOrganizationalUnit $Item  $OuWORKSTATIONS
                        $Ou = Add-ADOrganizationalUnit "DISABLED"  $OuLoc
                    }
                    $OuDEPARTMENTS = Add-ADOrganizationalUnit "DEPARTMENTS" $OuCompany
                    ForEach ($Item in $Departments) {
                        $OuDEPS = Add-ADOrganizationalUnit $Item $OuDEPARTMENTS
                        ForEach ($Item1 in $Global:OfficeLocations) {
                            $OuLoc = Add-ADOrganizationalUnit $Item1  $OuDEPS
                            $Ou = Add-ADOrganizationalUnit "DISABLED"  $OuLoc
                        }
                    }
                    $Global:ParentLevel --
                    Write-Host  "Generated organization units in [$ORGRootPath]."  -ForegroundColor Green              
                }

                Write-Host  "Adding users in AD." -ForegroundColor Green               
                $Global:ParentLevel ++
                foreach ($User in $Users) {    
                    if ($User.Enabled -eq "True") {
                        $Enabled = $true
                    }
                    Else {
                        $Enabled = $false
                    }
                    if ($User.ChangePasswordAtLogon -eq "True") {
                        $ChangePasswordAtLogon = $true
                    }
                    Else {
                        $ChangePasswordAtLogon = $false
                    }
                    if ($User.Department) {
                        $Department = $User.Department
                        $Office = $User.Division
                        $DepartmentsPath = (Get-ADOrganizationalUnit -Filter 'name -eq "DEPARTMENTS"' -SearchBase $ORGRootPath).DistinguishedName
                        $DepartmentPath = (Get-ADOrganizationalUnit -Filter 'name -eq $Department' -SearchBase $DepartmentsPath).DistinguishedName
                        $OfficePath = (Get-ADOrganizationalUnit -Filter 'name -eq $Office' -SearchBase $DepartmentPath ).DistinguishedName
                    }

                    if ($OfficePath) {
                        try {            
                            Write-Host "Adding user [$($User.DisplayName)] to [$Department] in [$Office]." -ForegroundColor Green  
                            New-ADUser `
                                -Name                  $User.Name `
                                -GivenName             $User.GivenName `
                                -Surname               $User.Surname `
                                -Department            $User.Department `
                                -State                 $User.State `
                                -EmployeeID            $User.EmployeeID `
                                -DisplayName           $User.DisplayName `
                                -SamAccountName        $User.SamAccountName `
                                -AccountPassword       $(ConvertTo-SecureString $User.AccountPassword -AsPlainText -Force) `
                                -Enabled               $Enabled `
                                -ChangePasswordAtLogon $ChangePasswordAtLogon `
                                -Path                  $OfficePath `
                                -Company               $User.Company `
                                -AllowReversiblePasswordEncryption  $User.AllowReversiblePasswordEncryption `
                                -Initials              $User.Initials `
                                -Division              $User.Division `
                                -OfficePhone           $User.OfficePhone `
                                -MobilePhone           $User.MobilePhone `
                                -Title                 $User.Title `
                                -Email                 $User.Email 
                        }
                        Catch {
                            Write-Host "Error while adding user [$($User.DisplayName)] to [$Department] in [$Office]! $_" -ForegroundColor Red
                        }
                    }
                }
                $Global:ParentLevel --
                Write-Host  "Added users in AD." -ForegroundColor Green                
                $Global:ParentLevel --
            }
            $ArgumentList = @{ UsersCount = $UsersCount } 
            $Res = Invoke-GuestWindowsCommand -VMName $VMName -GuestCredentials $GuestCredentials -Command $Command -ArgumentList $ArgumentList
        }
        Default {}
    }
    if ($RestartRequired) {
        Restart-CustomVM -Computer $Computer -Credentials $Credentials -VMName $VMName -RestartMode "Shutdown" 
        Start-Sleep -Seconds 20          
    }
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
   
        Set-GuestWindowsNetworkParameters -Computer $Computer -Credentials $Credentials -NetworkAdapter $NetworkAdapter -Network $Network -VMName $VMName -GuestCredentials $GuestCredentials -IPAddress $IPAddress -NetMask $NetMask  -DefaultGateway $DefaultGateway -DNSServers $DNSServers -Role $Role
    #>  
    [CmdletBinding()]   
    param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Remote host name." )]
        [ValidateNotNullOrEmpty()]
        [string]$Computer,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Credentials." )]
        [System.Management.Automation.PSCredential] $Credentials,
        [Parameter(Mandatory = $true,  Position = 2, HelpMessage = "VM name." )]
        [ValidateNotNull()]
        [string] $VMName,
        [Parameter( Mandatory = $True, Position = 3, HelpMessage = "VM Credentials." )]
        [System.Management.Automation.PSCredential] $GuestCredentials,
        [Parameter(Mandatory = $false, Position = 4, HelpMessage = "Network adapter." )]
        [ValidateNotNull()]
        $NetworkAdapter, 
        [Parameter(Mandatory = $true, Position = 5, HelpMessage = "Network parameters.", ParameterSetName = "Network parameters" )]
        [ValidateNotNull()]
        $Network,
        [Parameter(Mandatory = $true,  Position = 6, HelpMessage = "IP address.",        ParameterSetName = "IP" )]
        [ValidateNotNull()]
        [string] $IPAddress,
        [Parameter(Mandatory = $true,  Position = 7, HelpMessage = "Network mask.",      ParameterSetName = "IP" )]
        [ValidateNotNull()]
        [string] $NetMask,
        [Parameter(Mandatory = $true,  Position = 8, HelpMessage = "Default gateway.",   ParameterSetName = "IP" )]
        [ValidateNotNull()]
        [string] $DefaultGateway,
        [Parameter(Mandatory = $false, Position = 9, HelpMessage = "DNS servers list.",  ParameterSetName = "IP" )]
        [ValidateNotNull()]
        [string] $DNSServers,        
        [Parameter(Mandatory = $false, Position = 10, HelpMessage = "Host role.",        ParameterSetName = "Role" )]
        [ValidateSet("DomainController","Workstation","Server","Gateway")]
        [string] $Role
    ) 
    $ScriptBlock = {
        $ScriptBlock = {
            param(
                [Parameter(Mandatory = $true, Position = 1,  HelpMessage = "IP address." )]
                [ValidateNotNull()]
                [string] $IPAddress,
                [Parameter(Mandatory = $true, Position = 2,  HelpMessage = "Network mask." )]
                [ValidateNotNull()]
                [string] $NetMask,
                [Parameter(Mandatory = $true, Position = 3,  HelpMessage = "Default gateway." )]
                [ValidateNotNull()]
                [string] $DefaultGateway,
                [Parameter(Mandatory = $false, Position = 4, HelpMessage = "DNS servers list." )]
                [ValidateNotNull()]
                [string] $DNSServers,
                [Parameter(Mandatory = $true, Position = 5,  HelpMessage = "NIC number." )]
                [ValidateNotNull()]
                [int] $NICNumber
            ) 
            
            $NICs = Get-WMIObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Select-Object -first $NICNumber
            $NIC  = $NICs | Select-Object -Last 1            

            $NIC.EnableStatic($IPAddress , @($NetMask)) | out-null
            $NIC.SetGateways($DefaultGateway) | Out-Null
            if ($DNSServers) {
                $NIC.SetDNSServerSearchOrder($DNSServers) | Out-Null
            }
            $NIC.SetDynamicDNSRegistration("False") | Out-Null
        }

        if (-not $Using:NetworkAdapter) {
            $NetworkAdapter = Get-VM -name $Using:VMName | Get-VMNetworkAdapter | Where-Object { $_.SwitchName -eq $Using:Network.Switch.SwitchName } | Select-Object -first 1            
        }
        if (-not $Using:Role) {
            $Role = $Using:Network.role      
        }
        else {
            $Role = $Using:Role
        }

        $VMNetworkAdapters  = get-vm -name $Using:VMName | Get-VMNetworkAdapter
        $NICNameArray       = ($VMNetworkAdapters | select-object name).name
        $NICNumber          = [array]::IndexOf($NICNameArray, $NetworkAdapter.name) + 1
                        
        if ($Role -or ($Using:Network.Switch.config -eq $Using:NetworkConfigType.Static)) {
            $NetAddress   = $Using:Network.Switch.NetAddress
            $IpTriadArray = ($NetAddress.Split(".") | Select-Object -First 3)
            $IPRoles      = $Using:IPRoles
            switch ($Role) {
                "DomainController" { 
                    $NotUsedIP = $IPRoles.DomainController | Where-Object { $null -ne $_ } | Select-Object -first 1
                    if ($NotUsedIP) {
                        $IpTriadArray             += $IPRoles.DomainController
                        $IPRoles.DomainController  = $Null
                    }
                    Else {
                        throw "Role [DomainController] reached maximum capacity!"
                    }
                }
                "Workstation" { 
                    $NotUsedIP = $IPRoles.Workstation | Where-Object {$null -ne $_ } | select-object -first 1
                    if ($NotUsedIP) {
                        $IpTriadArray       += $NotUsedIP     
                        $IPRoles.Workstation = $IPRoles.Workstation -ne $NotUsedIP
                    }
                    Else {
                        throw "Role [Workstation] reached maximum capacity!"
                    }
                }
                "Server" { 
                    $NotUsedIP                             = $IPRoles.Server | Where-Object { $null -ne $_ } | Select-Object -first 1
                    if ($NotUsedIP) {
                        $IpTriadArray                         += $NotUsedIP
                        $IPRoles.Server                        = $IPRoles.Server -ne $NotUsedIP
                    }
                    Else {
                        throw "Role [Server] reached maximum capacity!"
                    }
                }
                "Gateway" { 
                    $NotUsedIP = $IPRoles.Gateway | Where-Object { $null -ne $_ } | Select-Object -first 1
                    if ($NotUsedIP) {
                        $IpTriadArray    += $IPRoles.Gateway
                        $IPRoles.Gateway  = $Null
                    }
                    Else {
                        throw "Role [Gateway] reached maximum capacity!"
                    }
                }
                Default {}
            }
            $IPAddress      = $IpTriadArray -join "."
            $NetMask        = $Using:Network.Switch.NetMask
            $DefaultGateway = $Using:Network.Switch.Gateway
            $DNSServers     = $Using:Network.Switch.DNS
        }
        else {
            $IPAddress      = $using:IPAddress
            $NetMask        = $using:NetMask
            $DefaultGateway = $using:DefaultGateway
            $DNSServers     = $using:DNSServers            
        }
        Invoke-Command -VMName $Using:VMName  -credential $Using:GuestCredentials -ScriptBlock $ScriptBlock -ArgumentList  $IPAddress, $NetMask, $DefaultGateway, $DNSServers, $NICNumber
        Return $IPRoles   
    }
    Set-Variable -Name "ExportedParameters1" -Value $PSBoundParameters -Scope "Global"
    $ExportedParameters1.IPRoles           = $IPRoles
    $ExportedParameters1.NetworkConfigType = $NetworkConfigType
    Add-ToLog -Message "Setting VM [$VMName] guest windows ip parameters." -logFilePath $ScriptLogFilePath -display -status "Info"
    $Global:IPRoles = Invoke-PSScriptBlock -Computer $Computer -Credential $Credentials -ScriptBlock $ScriptBlock -TestComputer -ExportedParameters $ExportedParameters1 
}


Export-ModuleMember -Function Set-KeyboardConfig, Set-DriveLabel, Set-GuestBGInfo, Start-WindowsInitialSetup, Get-GuestCredentials, Get-GuestWindowsOSVersion, Rename-WindowsGuest, Enable-RDPAccess, Set-WinTaskBand, Invoke-GuestWindowsCommand, Set-GuestWindowsNetworkParameters, Invoke-GuestWindowsCommandGroup