﻿<#	
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
	param (
		[Parameter(Mandatory = $true)] [string]$AccessToken,
        [Parameter(Mandatory = $true)] [string]$ClientId
	)

    process {

        $HttpRequesturl = "https://a.wunderlist.com/api/v1/user"
        $Result = Invoke-RestMethod -URI $HttpRequestUrl -Method Get -Headers @{ 'X-Access-Token' = $AccessToken; 'X-Client-ID' =  $ClientId } -ContentType "application/json"
        $Result
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
	param (
		[Parameter(Mandatory = $true)] [string]$AccessToken,
        [Parameter(Mandatory = $true)] [string]$ClientId
	)

    process {

        $HttpRequesturl =  "https://a.wunderlist.com/api/v1/lists"
        $Result = Invoke-RestMethod -URI $HttpRequestUrl -Method Get -Headers @{ 'X-Access-Token' = $AccessToken; 'X-Client-ID' =  $clientid } -ContentType "application/json"
        $Result
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
	param (
		[Parameter(Mandatory = $true)] [string]$AccessToken,
        [Parameter(Mandatory = $true)] [string]$ClientId
	)

    process {

        $HttpRequesturl =  "https://a.wunderlist.com/api/v1/reminders"
        $Result = Invoke-RestMethod -URI $HttpRequestUrl -Method Get -Headers @{ 'X-Access-Token' = $AccessToken; 'X-Client-ID' =  $clientid } -ContentType "application/json"
        $Result
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
  .LINK
  https://developer.wunderlist.com/documentation/endpoints/task

#>
	[CmdletBinding()]
	[OutputType('System.Management.Automation.PSCustomObject')]
	param (
		[Parameter(Mandatory = $true)] [string]$AccessToken,
        [Parameter(Mandatory = $true)] [string]$ClientId,
        [Parameter(Mandatory  =$true,ValueFromPipelineByPropertyName=$true)][string] [Alias("ListId")] $Id,
        [Parameter(Mandatory = $false)] [switch] $Completed
	)

    

    process {

    if ($Completed) {
        [string]$Compl = 'true' 
    }
    else
    {
        [string]$Compl = 'false' 
    }

        $HttpRequesturl =  "https://a.wunderlist.com/api/v1/tasks?list_id=$Id&completed=$Compl"
        $result = Invoke-RestMethod -URI $HttpRequestUrl -Method Get -Headers @{ 'X-Access-Token' = $AccessToken; 'X-Client-ID' =  $clientid } -ContentType "application/json"
        $result
    }
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
  .LINK
  https://developer.wunderlist.com/documentation/endpoints/task

#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)] [string]$AccessToken,
        [Parameter(Mandatory = $true)] [string]$ClientId,
        [Parameter(Mandatory=$true)]   [int]$listid,        
        [Parameter(Mandatory=$true)]   [string]$title
    )
    
    
        $HttpRequesturl =  'https://a.wunderlist.com/api/v1/tasks'
        $Body = "list_id=$listid, title=$title"

        $Body = "'list_id':$listid,'title':$title"
        $hashtable = @{'list_id' = $listid;
                       'title'= $title
                      }

        $body = ConvertTo-Json -InputObject $hashtable
        $result = Invoke-RestMethod -URI $HttpRequestUrl -Method POST -body $body -Headers @{ 'X-Access-Token' = $AccessToken; 'X-Client-ID' =  $clientid } -ContentType "application/json"
        $result
    
    
}

Export-ModuleMember -Function @( 'Get-oAuth2AccessToken',
    'Get-WunderlistUser',
    'Get-WunderlistTask',
    'Get-WunderlistReminder',
    'Get-WunderlistList',
    'New-WunderlistTask')

