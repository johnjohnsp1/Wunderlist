$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path).Replace(".Tests.ps1", ".psm1")
Import-Module -Force "$here\$sut"

InModuleScope -ModuleName WunderList {
    Describe 'Get-WunderlistUser' {
        It 'Requests data from Wunderlist correctly' {
    	    # -- Arrange (What is being set up and initialized in the arrange section)
            $url = 'https://a.wunderlist.com/api/v1/user'
            $requestFilter = {$RequestUrl -eq $url}
            Mock Get-WunderlistData -ParameterFilter $requestFilter -ModuleName Wunderlist
    	
    	    # -- Act (What method is being executed in the act section)
            Get-WunderlistUser
    	
    	    # -- Assert (What determines the outcome of the test in the assert section)
            Assert-MockCalled -CommandName Get-WunderlistData -Times 1 -ParameterFilter $requestFilter -ModuleName Wunderlist
        }
    }

    Describe 'Get-WunderlistList' {
        It 'Requests data from Wunderlist correctly' {
    	    # -- Arrange
            $url = 'https://a.wunderlist.com/api/v1/lists'
            $requestFilter = {$RequestUrl -eq $url}
            Mock Get-WunderlistData -ParameterFilter $requestFilter -ModuleName Wunderlist
    	
    	    # -- Act
            Get-WunderlistList
    	
    	    # -- Assert
            Assert-MockCalled -CommandName Get-WunderlistData -Times 1 -ParameterFilter $requestFilter -ModuleName Wunderlist
        }
    }

    Describe 'Get-WunderlistReminder' {
        It 'Requests data from Wunderlist correctly' {
    	    # -- Arrange
            $url = 'https://a.wunderlist.com/api/v1/reminders'
            $requestFilter = {$RequestUrl -eq $url}
            Mock Get-WunderlistData -ParameterFilter $requestFilter -ModuleName Wunderlist
    	
    	    # -- Act
            Get-WunderlistReminder
    	
    	    # -- Assert
            Assert-MockCalled -CommandName Get-WunderlistData -Times 1 -ParameterFilter $requestFilter -ModuleName Wunderlist
        }
    }

    Describe 'Get-WunderlistTask' {
        It 'Requests data from Wunderlist correctly' {
    	    # -- Arrange
            $parameters = @{
                Completed = $true
                Id = '0'
            }
            $url = Build-TaskUrl @parameters
            $requestFilter = {$RequestUrl -eq $url}
            Mock Get-WunderlistData -ParameterFilter $requestFilter -ModuleName Wunderlist

    	    # -- Act
            Get-WunderlistTask @parameters
    	
    	    # -- Assert
            Assert-MockCalled -CommandName Get-WunderlistData -Times 1 -ParameterFilter $requestFilter -ModuleName Wunderlist
        }
    }

    Describe 'Build-TaskUrl' {
        It 'Builds completed task url correcty' {
    	    # -- Arrange
    	    $expected = 'https://a.wunderlist.com/api/v1/tasks?list_id=10&completed=true'

    	    # -- Act
            $actual = Build-TaskUrl -Id 10 -Completed
        	
    	    # -- Assert
            $expected | Should Be $actual
        }
        
        It 'Builds not-completed task url correcty' {
    	    # -- Arrange
    	    $expected = 'https://a.wunderlist.com/api/v1/tasks?list_id=11&completed=false'

    	    # -- Act
            $actual = Build-TaskUrl -Id 11
        	
    	    # -- Assert
            $expected | Should Be $actual
        }
    }

    Describe 'Get-WunderlistData' {
        It 'Gets wunderlist data correctly' {
        	# -- Arrange
            $settings = New-AuthenticationSettings -ClientId "id" -AccessToken "token"
            Mock Load-AuthenticationSettings { $settings }

            $header = @{}
            Mock Build-AccessHeader { $header }

            $url = "url"
            $requestFilter = {($Uri -eq $url) -and ($Method -eq 'GET') -and ($ContentType -eq "application/json") -and ($Headers -eq $header) }
            Mock Invoke-RestMethod -ParameterFilter $requestFilter
            Mock Invoke-RestMethod {} #to prevent side effects
        	
            # -- Act
            Get-WunderlistData -RequestUrl $url
        	
        	# -- Assert
            Assert-MockCalled Invoke-RestMethod -ParameterFilter $requestFilter -Times 1
        }
    }

    Describe 'Build-AccessHeader' {
        It 'Builds access header correctly' {
    	    # -- Arrange
            $token = 'token'
            $client = 'client'

            $settings = New-AuthenticationSettings -AccessToken $token -ClientId $client
    	
    	    # -- Act
    	    $actual = Build-AccessHeader -AuthenticationSettings $settings

    	    # -- Assert
            $actual.'X-Access-Token' | Should Be $token    
            $actual.'X-Client-ID' | Should Be $client
        }
        
    }

    Describe 'New-WunderlistTask'{
        Context 'no parameter is provided' {
            It 'fails' {
             { New-WunderlistTask -Force } | Should Throw
            }
        } #End Context
        Context 'Create Wunderlist Task'   {
            It 'Creates Wunderlist task correctly' {
            # -- Arrange
            $parameters = @{    'listid'  = '164615123';
                                'title'  = 'Testing Wunderlist module';
                                'assignee_id'= '10404479';
                                'completed' = $true;
                                'recurrence_type'= 'day';
                                'recurrence_count'= '1';
                                'due_date'= '2015-06-30';
                                'starred'= $false;
                           }

            $settings = @{  'id'='1224718072';
                            'assignee_id'='10404479';
                            'created_at'='2015-07-01T10:57:41.656Z';
                            'created_by_id'='10404478';
                            'recurrence_type'='day';
                            'recurrence_count'='1';
                            'due_date'='2015-06-30';
                            'completed'='True';
                            'completed_at'='2015-07-01T10:57:41.656Z';
                            'completed_by_id'='10404478';
                            'starred'='False';
                            'list_id'='164615123';
                            'revision'='1';
                            'title'='Testing Wunderlist module';
                            'type'='task';
                        }
            Mock New-WunderlistTask {$settings}

            # -- Act
            New-WunderlistTask @params

            # -- Assert
            Assert-MockCalled -CommandName New-WunderlistTask -Times 1 -ModuleName Wunderlist
        }
   }
   }

#region Authentication
    Describe 'Get-Authentication' {
        It 'Gets authentication successfully' {
    	    # -- Arrange
            Mock Get-AuthenticationSettingsPath {
                'TestDrive:\Authentication.config.xml'
            }
    	
    	    # -- Act
    	    $actual = Get-Authentication 

    	    # -- Assert
            $Authentication    
        } -Pending
    }

    Describe 'Get-AuthenticationSettingsPath' {
        It 'Gets authentication settings path correctly' {
    	    # -- Arrange
            $expected = $script:AuthenticationSettingsPath 

    	    # -- Act
    	    $actual = Get-AuthenticationSettingsPath
        
    	    # -- Assert
            $actual | Should Not BeNullOrEmpty
            $actual | Should Be $expected
        }
    }

    Describe 'New-AuthenticationSettings' {
        It 'Creates new authentication settings object' {
    	    # -- Arrange
            $clientId = 'someid'
    	    $accessToken = 'accessToken'

    	    # -- Act
            $actual = New-AuthenticationSettings -ClientId $clientId -AccessToken $accessToken
        	
    	    # -- Assert
            $actual.ClientId | Should Be $clientId
            $actual.AccessToken |  Should Be $accessToken
        }
    }

    Describe 'Save-AuthenticationSettings' {
        It 'Saves authentication settings successfully' {
	        # -- Arrange
            $settingsPath = 'TestDrive:\Authentication.config.xml'
            $authenticationSettings = New-AuthenticationSettings -ClientId 'id' -AccessToken 'token'

            Mock Get-AuthenticationSettingsPath {
                $settingsPath
            }
            $exportCliXmlFilter =  {($Path -eq $settingsPath) -and ($InputObject -eq $authenticationSettings)}
            Mock Export-CliXml -ParameterFilter $exportCliXmlFilter
	
	        # -- Act
	        $actual = Save-AuthenticationSettings -AuthenticationSettings $authenticationSettings

	        # -- Assert
            Assert-MockCalled -CommandName Export-Clixml -Times 1 -ParameterFilter $exportCliXmlFilter
            Assert-MockCalled -CommandName Get-AuthenticationSettingsPath -Times 1
        }    
    }

    Describe 'Load-AuthenticationSettings' {
        It 'Loads authentication settings successfully' {
	        # -- Arrange
            $settingsPath = 'TestDrive:\Authentication.config.xml'
            $authenticationSettings = New-AuthenticationSettings -ClientId 'id' -AccessToken 'token'

            Mock Get-AuthenticationSettingsPath {
                $settingsPath
            }

            Mock Import-CliXml -ParameterFilter {($Path -eq $settingsPath)} {  $authenticationSettings }

	        # -- Act
	        $actual = Load-AuthenticationSettings

	        # -- Assert
            $actual | Should Be $authenticationSettings
        }    
    }
#endregion

}
