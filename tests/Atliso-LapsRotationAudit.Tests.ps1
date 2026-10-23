# Pester 5+. Windows LAPS and the event log are mocked, so these run anywhere:
#   Invoke-Pester ./tests

BeforeAll {
  $script:Script = Join-Path $PSScriptRoot '..\Atliso-LapsRotationAudit.ps1'

  # Stand-ins so the mocks have something to replace where Windows LAPS isn't installed.
  if (-not (Get-Command Reset-LapsPassword -ErrorAction SilentlyContinue)) { function global:Reset-LapsPassword { } }
  if (-not (Get-Command Get-WinEvent -ErrorAction SilentlyContinue)) { function global:Get-WinEvent { param($FilterHashtable, $ListLog) } }

  function script:Invoke-Audit([hashtable]$Params = @{}) {
    $p = @{ LogPath = (Join-Path $TestDrive 'laps.log') } + $Params
    $out = & $script:Script @p | Out-String
    [pscustomobject]@{ Exit = $LASTEXITCODE; Output = $out }
  }
}

Describe 'Atliso-LapsRotationAudit' {

  Context 'Atliso Pro contract' {
    It 'has exactly one [bool]$WhatIf parameter that Pro can flip for the detection and remediation copies' {
      $src = Get-Content $script:Script -Raw
      ([regex]::Matches($src, '(\[bool\]\$WhatIf\s*=\s*)\$(true|false)', 'IgnoreCase')).Count | Should -Be 1
      $src | Should -Match '\[bool\]\$WhatIf\s*=\s*\$true'
    }
  }

  It 'Entra backup event 10029 inside PasswordAgeDays + GraceDays: healthy, exit 0' {
    Mock Get-WinEvent { throw 'No events were found' } -ParameterFilter { $FilterHashtable.Id -eq 10005 }
    Mock Get-WinEvent { [pscustomobject]@{ Id = 10029 } } -ParameterFilter { $FilterHashtable.Id -eq 10029 }
    Mock Reset-LapsPassword { }
    $r = Invoke-Audit @{ WhatIf = $false }
    $r.Exit | Should -Be 0
    $r.Output | Should -Match 'Rotation is healthy'
    Should -Invoke Reset-LapsPassword -Times 0
  }

  It 'Active Directory destination looks for event 10018, not 10029' {
    Mock Get-WinEvent { throw 'No events were found' }
    Invoke-Audit @{ BackupDestination = 'ActiveDirectory' } | Out-Null
    Should -Invoke Get-WinEvent -ParameterFilter { $FilterHashtable.Id -eq 10018 -and $FilterHashtable.LogName -eq 'Microsoft-Windows-LAPS/Operational' }
    Should -Invoke Get-WinEvent -Times 0 -ParameterFilter { $FilterHashtable.Id -eq 10029 }
  }

  It 'the window is PasswordAgeDays + GraceDays' {
    Mock Get-WinEvent { throw 'No events were found' }
    Invoke-Audit @{ PasswordAgeDays = 14; GraceDays = 1 } | Out-Null
    Should -Invoke Get-WinEvent -ParameterFilter {
      $FilterHashtable.Id -eq 10029 -and
      $FilterHashtable.StartTime -gt (Get-Date).AddDays(-15).AddMinutes(-5) -and $FilterHashtable.StartTime -lt (Get-Date).AddDays(-15).AddMinutes(5)
    }
  }

  It 'no backup event with WhatIf: reports non-compliant, exit 1, no rotation' {
    Mock Get-WinEvent { throw 'No events were found' }
    Mock Reset-LapsPassword { }
    $r = Invoke-Audit
    $r.Exit | Should -Be 1
    $r.Output | Should -Match 'No confirmed LAPS backup'
    Should -Invoke Reset-LapsPassword -Times 0
  }

  It 'no backup event, remediation: forces rotation, exit 0' {
    Mock Get-WinEvent { throw 'No events were found' }
    Mock Reset-LapsPassword { }
    $r = Invoke-Audit @{ WhatIf = $false }
    $r.Exit | Should -Be 0
    Should -Invoke Reset-LapsPassword -Times 1 -Exactly
  }

  It 'Reset-LapsPassword failing exits 1' {
    Mock Get-WinEvent { throw 'No events were found' }
    Mock Reset-LapsPassword { throw 'Access denied' }
    $r = Invoke-Audit @{ WhatIf = $false }
    $r.Exit | Should -Be 1
    $r.Output | Should -Match 'Reset-LapsPassword failed'
  }

  It 'event 10005 in the last 24h is called out as actively failing' {
    Mock Get-WinEvent { @([pscustomobject]@{ Id = 10005 }, [pscustomobject]@{ Id = 10005 }) } -ParameterFilter { $FilterHashtable.Id -eq 10005 }
    Mock Get-WinEvent { throw 'No events were found' } -ParameterFilter { $FilterHashtable.Id -ne 10005 }
    $r = Invoke-Audit
    $r.Output | Should -Match 'Event 10005 .* logged 2 time\(s\)'
  }
}
