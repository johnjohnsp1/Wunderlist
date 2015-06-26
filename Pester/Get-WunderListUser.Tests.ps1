<#
  Pester provides a framework for running Unit Tests to execute and validate PowerShell commands inside of PowerShell.
  More info can be found here: 
  https://github.com/pester/Pester

  To test run the following command:
  invoke-pester from ..\Pester\ folder  
#>

Remove-Module Wunderlist -Force -ErrorAction SilentlyContinue

$scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path
cd $scriptRoot
Import-Module ..\Wunderlist.psd1 -Force -ErrorAction Stop

#Variables:
$name = "Stefan Stranger"
set-variable -name varsscv -value (import-csv -path .\variables.csv) -scope Global

Describe "Get-WunderListUser" {
Context "Mandatory AccessToken and ClientId parameters are provided" {
    It "outputs 'Wunderlist User name properties'" {
                (Get-WunderlistUser -AccessToken $varsscv.AccessToken -ClientId $varsscv.clientid).name | Should Be "$name"
    }
  }
Context "no AccessToken and ClientId parameters are provided. Hit enter during Pester test." {
      It "fails" {
           { Get-WunderlistUser } | Should Throw
      }
  }
}
