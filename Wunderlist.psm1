$script:AuthenticationSettingsPath = "$PSScriptRoot\Authentication.config.xml"

<#	
	===========================================================================
	 Created on:   	6/22/2015 12:00 PM
	 Created by:   	Stefan Stranger
	 Filename:     	Wunderlist.psm1
	-------------------------------------------------------------------------
	 Module Name: Wunderlist
	 Description: This Wunderlist PowerShell module was built to give a Wunderlist 
        user the ability to interact with Wunderlist via Powershell.

		Before importing this module, you must create your own Wunderlist application
		on https://developer.wunderlist.com and create an app.
		Once you do so, I recommend copying/pasting your
		Client ID and App URL to the
		parameters under the Get-OAuthAuthorization function.
	===========================================================================
#>


<#
 .Synopsis
 Retrieves an oAuth 2.0 access token from the specified base authorization
 URL, client application ID, and callback URL.

.Parameter AuthUrl
 The base authorization URL defined by the service provider.

.Parameter ClientId
 The client ID (aka. app ID, consumer ID, etc.).

.Parameter RedirectUri
 The callback URL configured on your application's registration with the
 service provider.

.Parameter SleepInterval
 The number of seconds to sleep while waiting for the user to authorize the
 application.
.EXAMPLE
 $DebugPreference = 'continue'; #Enable debug messages to be sent to console
 $AuthUrl = 'https://www.wunderlist.com/oauth/authorize'; # The base authorization URL from the service provider
 $ClientId = 'xxxxxxxxxxxxxxxxxxxx'; # Your registered application’s client ID
 $RedirectUri = 'http://www.stranger.nl'; # The callback URL configured on your application

 #Call Get-oAuth2AccessToken
   Get-oAuth2AccessToken `
    -AuthUrl $AuthUrl `
    -ClientId $ClientId `
    -RedirectUri $RedirectUri
.LINK
 http://trevorsullivan.net/2012/05/18/powershell-getting-an-access-token-from-instagram-oauth-2-0/
 #>

 function Get-oAuth2AccessToken {
 [CmdletBinding()]
 param (
 [Parameter(Mandatory = $false)] [string] $AuthUrl='https://www.wunderlist.com/oauth/authorize'
 , [Parameter(Mandatory = $true)] [string] $ClientId
 , [Parameter(Mandatory = $true)] [string] $RedirectUri
 , [int] $SleepInterval = 2
 )

# Build the request URL from a template
 $RequestUrl = '{0}?client_id={1}&redirect_uri={2}&response_type=token' `
-f $AuthUrl, $ClientId, $RedirectUri;
 Write-Debug -Message ('Request URL is: {0}’ -f $RequestUrl);

# Create the Internet Explorer object and navigate to the constructed authorization URL
 $IE = New-Object -ComObject InternetExplorer.Application;
 $IE.Navigate($RequestUrl);
 $IE.Visible = $true;

# Sleep the script for $X seconds until callback URL has been reached
 # NOTE: If user cancels authorization, this condition will not be satisifed
 while ($IE.LocationUrl -notmatch 'access_token=’) {
Write-Debug -Message ('Sleeping {0} seconds for access URL' -f $SleepInterval);
 Start-Sleep -Seconds $SleepInterval;
 }

# Parse the access token from the callback URL and exit Internet Explorer
 Write-Debug -Message ('Callback URL is: {0}' -f $IE.LocationUrl);
 [Void]($IE.LocationUrl -match '=([\w\.]+)');
 $global:AccessToken = $Matches[1];
 $IE.Quit();

# Write the access token to the pipeline inside of a HashTable (in case we want to return other properties later)
 Write-Debug -Message ('Access token is: {0}' -f $AccessToken);
 Write-Output -InputObject @{ AccessToken = $AccessToken; };
 }

function Get-WunderlistData 
{
    param (
        $RequestUrl
    )

    $settings = Load-AuthenticationSettings
    $headers = Build-AccessHeader -AuthenticationSettings $settings
    $result = Invoke-RestMethod -URI $RequestUrl -Method GET -Headers $headers -ContentType 'application/json'
    return $result
}

function Build-AccessHeader
{
    param (
        $AuthenticationSettings
    )

    @{ 
        'X-Access-Token' = $AuthenticationSettings.AccessToken
        'X-Client-ID' =  $AuthenticationSettings.ClientId 
     }
}

Function Get-WunderlistUser {
<#
  .SYNOPSIS
   This Function retrieves all info related to the currently signed in user.
  .DESCRIPTION
   This Function retrieves all info related to the currently signed in user.
  .EXAMPLE
   $DebugPreference = 'continue'; #Enable debug messages to be sent to console
   $AuthUrl = 'https://www.wunderlist.com/oauth/authorize'; # The base authorization URL from the service provider
   $ClientId = 'xxxxxxxxxxxxxxxxxxxx'; # Your registered application’s client ID
   $RedirectUri = 'http://www.stranger.nl'; # The callback URL configured on your application

   #Call Get-oAuth2AccessToken
   Get-oAuth2AccessToken `
    -AuthUrl $AuthUrl `
    -ClientId $ClientId `
    -RedirectUri $RedirectUri
   
   Get-WunderlistUser -AccessToken '619c400c87156477cce37b4369f1adf8b278437a027bdd83962ba44abeb5'
  .LINK
  https://developer.wunderlist.com/documentation/endpoints/user

#>
	[CmdletBinding()]
	[OutputType('System.Management.Automation.PSCustomObject')]
    param()

    process {
        Get-WunderlistData -RequestUrl 'https://a.wunderlist.com/api/v1/user'
    }
}


Function Get-WunderlistList {
<#
  .SYNOPSIS
   This Function retrieves all Lists a user has permission to.
  .DESCRIPTION
   This Function retrieves all Lists a user has permission to.
  .EXAMPLE
   $DebugPreference = 'continue'; #Enable debug messages to be sent to console
   $AuthUrl = 'https://www.wunderlist.com/oauth/authorize'; # The base authorization URL from the service provider
   $ClientId = 'xxxxxxxxxxxxxxxxxxxx'; # Your registered application’s client ID
   $RedirectUri = 'http://www.stranger.nl'; # The callback URL configured on your application

   #Call Get-oAuth2AccessToken
   Get-oAuth2AccessToken `
    -AuthUrl $AuthUrl `
    -ClientId $ClientId `
    -RedirectUri $RedirectUri
   
   Get-WunderlistList -AccessToken '619c400c87156477cce37b4369f1adf8b278437a027bdd83962ba44abeb5' `
        -ClientId '123456789'
  .LINK
  https://developer.wunderlist.com/documentation/endpoints/list

#>
	[CmdletBinding()]
	[OutputType('System.Management.Automation.PSCustomObject')]
    param()

    process {
        Get-WunderlistData -RequestUrl 'https://a.wunderlist.com/api/v1/lists'
    }
}

Function Get-WunderlistReminder {
<#
  .SYNOPSIS
   This Function retrieves Reminders for a Task or List.
  .DESCRIPTION
   This Function retrieves Reminders for a Task or List.
  .EXAMPLE
   $DebugPreference = 'continue'; #Enable debug messages to be sent to console
   $AuthUrl = 'https://www.wunderlist.com/oauth/authorize'; # The base authorization URL from the service provider
   $ClientId = 'xxxxxxxxxxxxxxxxxxxx'; # Your registered application’s client ID
   $RedirectUri = 'http://www.stranger.nl'; # The callback URL configured on your application

   #Call Get-oAuth2AccessToken
   Get-oAuth2AccessToken `
    -AuthUrl $AuthUrl `
    -ClientId $ClientId `
    -RedirectUri $RedirectUri
   
   Get-WunderlistReminder -AccessToken '619c400c87156477cce37b4369f1adf8b278437a027bdd83962ba44abeb5' `
        -ClientId '123456789'
  .LINK
  https://developer.wunderlist.com/documentation/endpoints/reminderlist

#>
	[CmdletBinding()]
	[OutputType('System.Management.Automation.PSCustomObject')]
	param (	)

    process {
        Get-WunderlistData -RequestUrl 'https://a.wunderlist.com/api/v1/reminders'
    }
}

Function Get-WunderlistTask {
<#
  .SYNOPSIS
   This Function retrieves Reminders for a Task or List.
  .DESCRIPTION
   This Function retrieves Reminders for a Task or List.
  .EXAMPLE
   $DebugPreference = 'continue'; #Enable debug messages to be sent to console
   $AuthUrl = 'https://www.wunderlist.com/oauth/authorize'; # The base authorization URL from the service provider
   $ClientId = 'xxxxxxxxxxxxxxxxxxxx'; # Your registered application’s client ID
   $RedirectUri = 'http://www.stranger.nl'; # The callback URL configured on your application

   #Call Get-oAuth2AccessToken
   Get-oAuth2AccessToken `
    -AuthUrl $AuthUrl `
    -ClientId $ClientId `
    -RedirectUri $RedirectUri
   
   Get WunderList Tasks for List 164615234 where tasks are completed
   Get-WunderlistTask -AccessToken '619c400c87156477cce37b4369f1adf8b278437a027bdd83962ba44abeb5' `        -ClientId '123456789' ListId 164615234 -Completed
  .EXAMPLE
   $DebugPreference = 'continue'; #Enable debug messages to be sent to console
   $AuthUrl = 'https://www.wunderlist.com/oauth/authorize'; # The base authorization URL from the service provider
   $ClientId = 'xxxxxxxxxxxxxxxxxxxx'; # Your registered application’s client ID
   $RedirectUri = 'http://www.stranger.nl'; # The callback URL configured on your application

   #Call Get-oAuth2AccessToken
   Get-oAuth2AccessToken `
    -AuthUrl $AuthUrl `
    -ClientId $ClientId `
    -RedirectUri $RedirectUri
   
   Get WunderList Tasks for List 164615234 where tasks are not completed
   Get-WunderlistTask -AccessToken '619c400c87156477cce37b4369f1adf8b278437a027bdd83962ba44abeb5' `        -ClientId '123456789' ListId 164615234
  .EXAMPLE
  Get Wunderlist List and pipe the results into Get-WunderlistTasks cmdlet
  Get-WunderlistList -AccessToken '619c400c87156477cce37b4369f1adf8b278437a027bdd83962ba44abeb5' `
       -ClientId '123456789' | Get-WunderlistTask -AccessToken '619c400c87156477cce37b4369f1adf8b278437a027bdd83962ba44abeb5' `
       -ClientId '123456789'
  .EXAMPLE
  Get all Wunderlist Tasks grouped by Wunderlist lists.
  get-wunderlistlist | get-wunderlisttask | Format-Table id, title, completed, created_at -GroupBy list_id
  .LINK
  https://developer.wunderlist.com/documentation/endpoints/task

#>
	[CmdletBinding()]
	[OutputType('System.Management.Automation.PSCustomObject')]
	param (
        [Parameter(Mandatory  =$true,ValueFromPipelineByPropertyName=$true)][string] [Alias("ListId")] $Id,
        [Parameter(Mandatory = $false)] [switch] $Completed
	)

    process {
        $requesturl =  Build-TaskUrl -Id $Id -Completed $Completed
        Get-WunderlistData -RequestUrl $requesturl
    }
}

function Build-TaskUrl {
    param (
        $Id, 
        [switch]$Completed
    )

    'https://a.wunderlist.com/api/v1/tasks?list_id={0}&completed={1}' -f $Id, $Completed.ToString().ToLower()
}

Function New-WunderlistTask
{
<#
  .SYNOPSIS
   This Function Creates  new Wunderlist Task for a specified List.
  .DESCRIPTION
   This Function Creates  new Wunderlist Task for a specified List.
  .EXAMPLE
   $DebugPreference = 'continue'; #Enable debug messages to be sent to console
   $AuthUrl = 'https://www.wunderlist.com/oauth/authorize'; # The base authorization URL from the service provider
   $ClientId = 'xxxxxxxxxxxxxxxxxxxx'; # Your registered application’s client ID
   $RedirectUri = 'http://www.stranger.nl'; # The callback URL configured on your application

   #Call Get-oAuth2AccessToken
   Get-oAuth2AccessToken `
    -AuthUrl $AuthUrl `
    -ClientId $ClientId `
    -RedirectUri $RedirectUri
   
   New-WunderlistTask -AccessToken '619c400c87156477cce37b4369f1adf8b278437a027bdd83962ba44abeb5' `
       -ClientId '123456789' -listid '16461524' -title 'Testing Wunderlist PowerShell module'
  .EXAMPLE
   $params = @{'clientid' = 'f8fee9ecf6f094efrdg';
               'accesstoken'  = 'babc2e1a0875af11360ac696c9170ced709d729704e4d6cc123456789h5f'
               'listid'  = '164611234';
               'title'  = 'Testing posh module';
               'assignee_id'= '10401234';
               'completed' = $true;
               'recurrence_type'= 'day';
               'recurrence_count'= '2';
               'due_date'= '2015-06-30';
               'starred'= $false;
              }
    New-WunderlistTask @params

  .LINK
  https://developer.wunderlist.com/documentation/endpoints/task

#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]  [string]$AccessToken,
        [Parameter(Mandatory = $false)]  [string]$ClientId,
        [Parameter(Mandatory = $true)]   [int]$listid,        
        [Parameter(Mandatory = $true)]   [string]$title,
        [Parameter(Mandatory = $false)]  [int]$assignee_id,
        [Parameter(Mandatory = $false, ParameterSetName='Recurrence')]  
                                         [bool]$completed,
        [ValidateSet("day", "week", "month","year")]
        [Parameter(Mandatory = $false, ParameterSetName='Recurrence')]
                                         [string]$recurrence_type,
        [Parameter(Mandatory = $false)]  [int]$recurrence_count,
        [Parameter(Mandatory = $false)] 
        [ValidatePattern("^(19|20)\d\d[-](0[1-9]|1[012])[-](0[1-9]|[12][0-9]|3[01])")]      
                                         [string]$due_date,
        [Parameter(Mandatory = $false)]  [bool]$starred

    )
    
    
        $HttpRequesturl =  'https://a.wunderlist.com/api/v1/tasks'

        $hashtable = [ordered]@{'list_id'   = $listid;
                       'title'              = $title;
                       'assignee_id'        = $assignee_id;
                       'completed'          = $completed;
                       'recurrence_type'    = $recurrence_type;
                       'recurrence_count'   = $recurrence_count;
                       'due_date'           = $due_date;
                       'starred'            = $starred;
                      }
        $body = ConvertTo-Json -InputObject $hashtable
        $settings = Load-AuthenticationSettings #new in version 1.1
        $headers = Build-AccessHeader -AuthenticationSettings $settings #new in version 1.1
        $result = Invoke-RestMethod -URI $HttpRequestUrl -Method POST -body $body -Headers $headers -ContentType 'application/json'
        $result
    
    
}

Function New-WunderlistFileUpload
{
<#
  .SYNOPSIS
   This Function Creates new Wunderlist Upload.
  .DESCRIPTION
   This Function Creates new Wunderlist Upload.
   Current limitation is that only plain text files work correctly and the content type is hardcoded.
   Future release will determine content type correctly 
  .EXAMPLE
   $DebugPreference = 'continue'; #Enable debug messages to be sent to console
   $AuthUrl = 'https://www.wunderlist.com/oauth/authorize'; # The base authorization URL from the service provider
   $ClientId = 'xxxxxxxxxxxxxxxxxxxx'; # Your registered application’s client ID
   $RedirectUri = 'http://www.stranger.nl'; # The callback URL configured on your application

   #Call Get-oAuth2AccessToken
   Get-oAuth2AccessToken `
    -AuthUrl $AuthUrl `
    -ClientId $ClientId `
    -RedirectUri $RedirectUri
   
   New-WunderlistFileUpload -FileName readme.txt
  .LINK
  https://developer.wunderlist.com/documentation/endpoints/upload

#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]   [string]$FileName,
        [Parameter(Mandatory=$true)]   [int]$TaskId        
    )
          
        $drive = Get-PSDrive HKCR -ErrorAction SilentlyContinue;
        if ( $null -eq $drive )
        {
            $drive = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
        }


        [int]$FileSize = (Get-Item $FileName).length
        [string]$ContentType = (Get-ItemProperty HKCR:$((Get-Item $FileName).Extension)).'Content Type';

        Write-Debug "Following content type detected: $ContentType"

        if($ContentType -eq ''){
            $ContentType = 'octet/stream'
            }
   
        $HttpRequesturl =  'https://a.wunderlist.com/api/v1/uploads'

        $hashtable = @{'content_type' = $ContentType;
                       'file_name' = $(Get-Item $FileName).Name;
                       'file_size' = $FileSize
                      }
        $body = ConvertTo-Json -InputObject $hashtable

        $settings = Load-AuthenticationSettings
        $headers = Build-AccessHeader -AuthenticationSettings $settings

        $result = Invoke-RestMethod -URI $HttpRequestUrl -Method post -body $body -Headers $headers -ContentType 'application/json'
        $result
        
        if($result.state = "new"){
            $headers = @{ 'Authorization' = $result.part.authorization; 'x-amz-date' =  $result.part.date; 'Content-Type' =  "" }
            $body = get-content $FileName -Encoding Byte -Raw
            Invoke-RestMethod -URI $result.part.url -Method Put -body $body -Headers $headers
            }

        $UploadId = $result.id
        
        $HttpRequesturl =  'https://a.wunderlist.com/api/v1/uploads/' + $UploadId
        $State = "finished"

        $hashtable = @{'state' = $State
                      }
        $body = ConvertTo-Json -InputObject $hashtable

        $settings = Load-AuthenticationSettings
        $headers = Build-AccessHeader -AuthenticationSettings $settings

        $result = Invoke-RestMethod -URI $HttpRequestUrl -Method PATCH -body $body -headers $headers -ContentType 'application/json'
        $result 

        $HttpRequesturl =  'https://a.wunderlist.com/api/v1/files/'
        
        $hashtable = @{'upload_id' = $UploadId;
                       'task_id' = $TaskId;
                      }

        $body = ConvertTo-Json -InputObject $hashtable
               
        $settings = Load-AuthenticationSettings
        $headers = Build-AccessHeader -AuthenticationSettings $settings        
        
        $result = Invoke-RestMethod -URI $HttpRequestUrl -Method POST -body $body -headers $headers -ContentType 'application/json'
        $result 
}

Function Remove-WunderlistTask
{
<#
  .SYNOPSIS
   This Function deletes Wunderlist task.
  .DESCRIPTION
   This Function deletes Wunderlist task.
  .EXAMPLE
   Remove Wunderlist Task with id 123456
   Remove-WunderlistTask -id 123456
  .EXAMPLE
   Remove Wunderlist Task with id 123456 and revision number 1 with whatif switch
   Remove-WunderlistTask -id 123456 -whatif
  .EXAMPLE
   Retrieve all Wunderlist tasks and delete all completed tasks
   Get-
   Remove-WunderlistTask -id 123456 -whatif
  .EXAMPLE
   Confirm the deletion of each Wunderlist Task which is completed
   get-wunderlistlist | get-wunderlisttask | Where-Object {$_.completed -eq $true} | Remove-WunderlistTask -Confirm
  .LINK
  https://developer.wunderlist.com/documentation/endpoints/task

#>
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    param
    (
        [Parameter(Mandatory = $false)]  [string]$AccessToken,
        [Parameter(Mandatory = $false)]  [string]$ClientId,
        [Parameter(Mandatory  =$true,ValueFromPipelineByPropertyName=$true)]   [string] [Alias("TaskId")] $Id
    )

    process {

        $Wunderlisttask = get-wunderlistList | get-wunderlisttask | Where-Object {$_.id -eq $id} 

        If ($pscmdlet.ShouldProcess($Wunderlisttask.title, "Deleting WunderlistTask"))
        {
            $revision = $Wunderlisttask.revision

            $HttpRequestUrl = 'https://a.wunderlist.com/api/v1/tasks/{0}?revision={1}' -f $id, $revision 
               
            $settings = Load-AuthenticationSettings
            $headers = Build-AccessHeader -AuthenticationSettings $settings        
        
            $result = Invoke-RestMethod -URI $HttpRequestUrl -Method DELETE -headers $headers
            $result 
        }
        
    }
}


#region Authentication
function Get-AuthenticationSettingsPath 
{
    $script:AuthenticationSettingsPath
}

function New-AuthenticationSettings
{
    param (
        $ClientId,
        $AccessToken
    )

    New-Object -TypeName psObject -Property @{
        ClientId = $ClientId
    	AccessToken = $AccessToken
    }
}

function Save-AuthenticationSettings {
    param (
        $AuthenticationSettings
    )

    $path = Get-AuthenticationSettingsPath
    Export-Clixml -Path $path -InputObject $AuthenticationSettings
}

function Load-AuthenticationSettings {
    $path = Get-AuthenticationSettingsPath
    Import-Clixml -Path $path
}
#endregion

Export-ModuleMember -Function @( 'Get-oAuth2AccessToken',
    'Get-WunderlistUser',
    'Get-WunderlistTask',
    'Get-WunderlistReminder',
    'Get-WunderlistList',
    'New-WunderlistTask',
    'Remove-WunderlistTask',
    'New-WunderlistFileUpload',
    'New-AuthenticationSettings',
    'Save-AuthenticationSettings',
    'Load-AuthenticationSettings')

