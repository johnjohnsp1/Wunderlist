# these Pester tests are acceptance tests, we are making sure the way we communicate
# with the real service are correct, so you need to be authenticated with the web service

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module -Force "$here\Wunderlist.psd1"

Describe "Get-WunderListList" {
    It 'Inbox WunderList List is retrived correctly' {
        # -- Arrange
        $expected = $listName = 'Inbox'
        	
        # -- Act
        $lists = Get-WunderlistList
        $inboxList = $lists | where {$_.title -eq $listName} 
        $actual = $inboxList.Title

        # -- Assert
        $actual | Should Be $expected 
    }
}

Describe 'Get-WunderListUser' {
    It 'Outputs username correctly' {
    	# -- Arrange
    	
    	# -- Act
        $user = Get-WunderlistUser
        $actual = $user.Name 
    	
    	# -- Assert
        $actual | Should Not BeNullOrEmpty 
    }
}


Describe 'New-WunderListTask' {
    It 'Outputs created Wunderlist Task correctly' {
    	# -- Arrange
        $listboxid = (Get-WunderlistList | where-object {$_.title -eq 'inbox'}).id
    	$expected = $listboxid
        $parameters = @{'listid'  = $listboxid;
                        'title'  = 'Testing Wunderlist module';
                        'completed' = $true;
                       } 
    	# -- Act
        $task = New-WunderlistTask @parameters
        $actual = $task.title 
    	
    	# -- Assert
        $actual | Should Not BeNullOrEmpty 
    }
}
