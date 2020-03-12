<#
.SYNOPSIS
    This script simply looks for unquoted service paths and checks for write permission to the paths
.DESCRIPTION
    Unquoted service path is not a good security practice and could create opportunity for malicious actors
    in privilege escalation if the services are running under higher privileges.

    This script simply looks for unquoted service paths and checks for write permission to the paths.

.EXAMPLES
    PS C:\Users\rajnepali\Desktop> .\unquotedservicepaths.ps1
#>

Write-Output("[+] Searching for Unquoted Service Paths")
Write-Output("[+] Getting Services")
$service = Get-CimInstance -Class Win32_Service | Select Name, PathName
Write-Output("[+] Extracting interesting Paths...")

# Lets define array for the paths identified
$vuln_services = @()
ForEach ($item in $service)
{
    #If the pathname is inside the quote then ignore
    if($item.PathName -match '\"')
    {
        #Do-Nothing
    }
    else
    {   
        #These PathNames are not inside quote so move on
        #if the pathname contains whitespace, add it to the list
        if($item.PathName -match "\s")
        {
            if($item.PathName -match "svchost") #ignoring svchost
            {
                #Ignore
            }
            else
            {
                #Add it to the vulnerable services list
                $vuln_services += $item
            }
        } 
    }
}

Write-Output("[+] Normalizing paths....")

$final_vuln_services = @()
$current_dir = Get-Location | select -ExpandProperty Path
#Lets check the user 
$context = New-Object Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent()) 
if($context.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host("[+] Awesome! you have admin rights :) ")
	$user = "BUILTIN\Administrators"
}
else{
	$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

Write-Host("[+] Checking permission for: $user ")

foreach($item in $vuln_services) #Name, PathName
{
    $path_to_test = @()
    $temp_array = @()
    #Lets split the path based on the space and get the first item and add it to new array
    $temp_array = ($item.PathName).split(" ")
    $path_to_test += $temp_array[0]

    foreach($path in $path_to_test)
    {
        #Can I write at this path??
        #lets find the path to work on :). The idea here is to move one directory back and checking permission

        $temp = $path.split("\")
        $try_path=""
        for ($i=0; $i -lt ($temp.Length - 1); $i++)
        {
            $try_path += $temp[$i] + "\"
        }
        #Now that I have a path lets check the permission
        $permission = (Get-ACL $try_path).Access | Where-Object {$_.IdentityReference -eq $user} | select -ExpandProperty FileSystemRights
        if($permission -contains "FullControl")
        {
            $final_vuln_services += $item
        }
        else 
        { 
            #Do Nothing
        }
        
    }
}
Set-Location $current_dir
if($final_vuln_services.Length -gt 0)
{
   Write-Host("`n[=>] All Writeable Unquoted Service Name and Paths found are below: `n")
   $final_vuln_services
}
else
{
    Write-Output("[!] Oops, Sorry! Maybe try another way :(")
}
