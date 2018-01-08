#Requires -Version 3
function Set-Permissions{
    <#
        .SYNOPSIS
            Changes owner of a file or folder to another user or group and add user(s) and/or group(s) with full permissions.

        .DESCRIPTION
            Changes owner of a file or folder to another user or group and add user(s) and/or group(s) with full permissions.

        .PARAMETER Path
            The folder or file that will have the owner changed.

        .PARAMETER Owner
            Optional parameter to change owner of a file or folder to specified account.

            Default value is 'VORDEFINIERT\Administratoren'

        .PARAMETER AddSecurityObjects
            Optional paramter to add Full Access rights for the spcified account(s).

            Default value is 'VORDEFINIERT\Administratoren'

        .PARAMETER RemoveSecuirtyObjects
            Optional paramter to remove Full Access rights from the spcified account(s).

        .PARAMETER Recurse
            Recursively set ownership and full permissions on subfolders and files beneath given folder.

        .NOTES
            Name: Set-Permissions
            Author: John Schärli
            Version History:
                 1.0 - John Schärli
                    - Initial Version

        .EXAMPLE
            Set-Permissions -Path C:\temp\test.txt

            Description
            -----------
            Changes the owner of test.txt to 'VORDEFINIERT\Administratoren' and grant them full accessrights to test.txt

        .EXAMPLE
            Set-Permissions -Path C:\temp\test.txt -Owner 'Domain\User'

            Description
            -----------
            Changes the owner of test.txt to Domain\User and grant VORDEFINIERT\Administratoren full accessrights to test.txt

        .EXAMPLE
            Set-Permissions -Path C:\temp -Recurse 

            Description
            -----------
            Changes the owner of all files and folders under C:\Temp to VORDEFINIERT\Administratoren

        .EXAMPLE
            Get-ChildItem C:\Temp | Set-Permissions -Recurse -Owner 'Domain\User'

            Description
            -----------
            Changes the owner of all files and folders under C:\Temp to Domain\User

        .EXAMPLE
            Set-Permissions -Path C:\temp\test.txt -Owner 'Domain\User' -AddSecurityObjects 'Domain\User'

            Description
            -----------
            Changes the owner of test.txt to Domain\User and grant them full accessrights to test.txt

        .EXAMPLE
            Set-Permissions -Path C:\temp\test.txt -Owner 'Domain\User' -AddSecurityObjects 'Domain\User' -RemoveSecuirtyObjects 'domain\otheruser'

            Description
            -----------
            Changes the owner of test.txt to Domain\User and grant them full accessrights to test.txt and remove permission for 'domain\otheruser' from file test.txt (Not inherited rights)         
    #>
    [cmdletbinding(
        SupportsShouldProcess = $True
    )]
    Param (
        # The folder or file that will have the owner changed.
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName')]
        [string[]]
        $Path,

        # Optional parameter to change owner of a file or folder to specified account.
        [parameter()]
        [ValidateScript({
            $result = $true
            try{
                [void]([System.Security.Principal.NTAccount]$item).Translate([System.Security.Principal.SecurityIdentifier])
            }catch{
                $result = $false
                throw "error"
            }
            return $result
        })]
        [string]
        $Owner = 'VORDEFINIERT\Administratoren',

        # Optional paramter to add Full Access rights for the spcified account(s).
        [Parameter()]
        [ValidateScript({
            foreach($item in $_){
                $result = $true
                try{
                    [void]([System.Security.Principal.NTAccount]$item).Translate([System.Security.Principal.SecurityIdentifier])
                }catch{
                    $result = $false
                    throw "error"
                }
            }return $result
        })]
        [string[]]
        $AddSecurityObjects = 'VORDEFINIERT\Administratoren',

        # Optional paramter to remove Full Access rights from the spcified account(s).
        [Parameter()]
        [string[]]
        $RemoveSecuirtyObjects,

        # Recursively set ownership and full permissions on subfolders and files beneath given folder.
        [parameter()]
        [switch]
        $Recurse
    )
    begin{
        #Prevent Confirmation on each Write-Debug command when using -Debug
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        Try {
            [void][TokenAdjuster]
        } Catch {
            $AdjustTokenPrivileges = @"
            using System;
            using System.Runtime.InteropServices;

             public class TokenAdjuster
             {
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
              ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
              [DllImport("kernel32.dll", ExactSpelling = true)]
              internal static extern IntPtr GetCurrentProcess();
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
              phtok);
              [DllImport("advapi32.dll", SetLastError = true)]
              internal static extern bool LookupPrivilegeValue(string host, string name,
              ref long pluid);
              [StructLayout(LayoutKind.Sequential, Pack = 1)]
              internal struct TokPriv1Luid
              {
               public int Count;
               public long Luid;
               public int Attr;
              }
              internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
              internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
              internal const int TOKEN_QUERY = 0x00000008;
              internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
              public static bool AddPrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_ENABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
              public static bool RemovePrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_DISABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
             }
"@
            Add-Type $AdjustTokenPrivileges

        }finally {
            #Activate necessary admin privileges to make changes without NTFS perms
            [void][TokenAdjuster]::AddPrivilege("SeRestorePrivilege") #Necessary to set Owner Permissions
            [void][TokenAdjuster]::AddPrivilege("SeBackupPrivilege") #Necessary to bypass Traverse Checking
            [void][TokenAdjuster]::AddPrivilege("SeTakeOwnershipPrivilege") #Necessary to override FilePermissions
        }
        # https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights
        $colRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
        # https://msdn.microsoft.com/en-us/library/system.secfflurity.accesscontrol.inheritanceflags
        # ContainerInherit      - The ACE is inherited by child container objects.
        # None	                - The ACE is not inherited by child objects.
        # ObjectInherit	        - The ACE is inherited by child leaf objects.
        $InheritanceFlagDir = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
        $InheritanceFlagFile = [System.Security.AccessControl.InheritanceFlags]::None
        # https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.propagationflags
        # None                  - Specifies that no inheritance flags are set.
        # NoPropagateInherit    - Specifies that the ACE is not propagated to child objects.
        # InheritOnly           - Specifies that the ACE is propagated only to child objects. This includes both container and leaf child objects. 
        $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None 
        # https://msdn.microsoft.com/en-us/library/w4ds5h86
        # Allow                 - The AccessRule object is used to allow access to a secured object.
        # Deny	                - The AccessRule object is used to deny access to a secured object.
        $objType = [System.Security.AccessControl.AccessControlType]::Allow
        $MaxPathLength = 260

    }Process{
        foreach ($Item in $Path){
            Write-Verbose "FullName: $Item"

            try {
                $Item = Get-Item -LiteralPath $Item -Force -ErrorAction Stop

                #The ACL objects do not like being used more than once, so re-create them on the Process block
                $DirOwner = New-Object System.Security.AccessControl.DirectorySecurity
                $FileOwner = New-Object System.Security.AccessControl.FileSecurity
                $DirOwner.SetOwner([System.Security.Principal.NTAccount]$Owner)
                $FileOwner.SetOwner([System.Security.Principal.NTAccount]$Owner)

                If (-NOT $Item.PSIsContainer) {
                    # Process File
                    If ($PSCmdlet.ShouldProcess($Item, 'Set file owner and access rights')) {
                        Try {
                            ##Add Owner to file
                            $Item.SetAccessControl($FileOwner)
                            
                            ##Change Permissions
                            #get ACL from item
                            $ACL = $item.GetAccessControl()
                            
                            <#
                            #Add Full Permision for Users to File (Disabeld)
                            foreach ($SecurityObject in $AddSecurityObjects) {
                                try {
                                    $FileACEAdd = New-Object System.Security.AccessControl.FileSystemAccessRule($SecurityObject, $colRights, $InheritanceFlagFile, $PropagationFlag, $objType)
                                    $ACL.AddAccessRule($FileACEAdd)
                                } catch {
                                    Write-Warning "$($SecurityObject): $($_.Exception.Message)"
                                }
                            } 
                            #>

                            #Enable access rule inherance for the file
                            $ACL.SetAccessRuleProtection($False, $True)

                            #Remove access from file for mentioned user(s) and/or group(s)
                            foreach ($SecurityObject in $RemoveSecuirtyObjects) {
                                $ACEs = $ACL.Access | Where-Object {$_.IdentityReference -eq $SecurityObject}
                                if($ACEs){
                                    Write-Verbose "Remove ACE from $Item $($ACEs | Format-Table | Out-String)"
                                }
                                
                                foreach ($ACE in $ACEs) {
                                    try {
                                        $null = $ACL.RemoveAccessRule($ACE)
                                    }
                                    catch {
                                        Write-Error -Message "$($SecurityObject): $($_.Exception.Message)"
                                    }
                                }
                            }
                            $item.SetAccessControl($ACL)
                        } Catch {
                            Write-Warning "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Directory.FullName)"
                            $Item.Directory.SetAccessControl($DirOwner)
                            $Item.SetAccessControl($FileOwner)
                        }
                    }
                } Else {
                    #Process Directorys
                    If ($PSCmdlet.ShouldProcess($Item, 'Set Directory Owner and Rights')) {                        
                        Try {
                            #Add Owner to directory
                            $Item.SetAccessControl($DirOwner)

                            #ACL
                            $ACL = $Item.GetAccessControl()

                            foreach ($SecurityObject in $AddSecurityObjects) {
                                try {
                                    $DirACEAdd = New-Object System.Security.AccessControl.FileSystemAccessRule($AddSecurityObjects, $colRights, $InheritanceFlagDir, $PropagationFlag, $objType)
                                    $ACL.AddAccessRule($DirACEAdd)
                                } catch {
                                    Write-Warning "$($SecurityObject): $($_.Exception.Message)"
                                }
                            }
                            
                            #Remove access from file for mentioned user(s) and/or group(s)
                            foreach ($SecurityObject in $RemoveSecuirtyObjects) {
                                $ACEs = $ACL.Access | Where-Object {$_.IdentityReference -eq $SecurityObject}
                                if($ACEs){
                                    Write-Verbose "Remove ACE  from $Item $($ACEs | Format-Table | Out-String)"
                                }
                                foreach ($ACE in $ACEs) {
                                    try {
                                        $null = $ACL.RemoveAccessRule($ACE)
                                    }
                                    catch {
                                        Write-Error -Message "$($SecurityObject): $($_.Exception.Message)" 
                                    }
                                }
                            }

                            $Item.SetAccessControl($ACL)
                        } Catch {
                            Write-Warning "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Parent.FullName)"
                            $Item.Parent.SetAccessControl($DirOwner) 
                            $Item.SetAccessControl($DirOwner)
                        }
                    }
                    If ($Recurse) {
                        [void]$PSBoundParameters.Remove('Path')
                        $MaxChildPathLength = ($(Get-ChildItem).FullName | Measure-Object -Maximum -Property Length).Maximum
                        
                        #Workaround for long Paths
                        if ($MaxChildPathLength -ge $MaxPathLength) {
                            Write-Warning "to long with $MaxChildPathLength : $Path "
                            New-PSDrive -Name T -PSProvider FileSystem -Root $item.FullName -Persist
                            Get-ChildItem "t:\" -Force | Set-Permissions @PSBoundParameters
                            Remove-PSDrive -Name T
                        }else {
                            Get-ChildItem $Item -Force | Set-Permissions @PSBoundParameters
                        }
                        
                    }
                }


        
            }
            catch {
                Write-Warning "$($Item): $($_.Exception.Message)"
            }
        }


        
    }
    end{
        #Remove priviledges that had been granted
        [void][TokenAdjuster]::RemovePrivilege("SeRestorePrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeBackupPrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeTakeOwnershipPrivilege")   
    }
        
}