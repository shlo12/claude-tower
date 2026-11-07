[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$ErrorActionPreference = 'Stop'
$result = @{ RouteKnown=$false; TunRoute=$false; TunName=''; V6Safe=$false; Direct=$false; ConnectionsKnown=$false; ClaudePath=''; LaunchId='' }
try {
 $route = Find-NetRoute -RemoteIPAddress '1.1.1.1' | Where-Object { $_.DestinationPrefix } | Select-Object -Last 1
 $adapter = Get-NetAdapter -IncludeHidden | Where-Object { $_.ifIndex -eq $route.InterfaceIndex } | Select-Object -First 1
 $result.RouteKnown = $true
 $result.TunName = [string]$adapter.Name + ' #' + [string]$route.InterfaceIndex + ' ' + [string]$route.NextHop
 $result.TunRoute = (($adapter.Status -eq 'Up') -and (-not $adapter.HardwareInterface) -and (($adapter.Name + ' ' + $adapter.InterfaceDescription) -match 'mihomo|clash|wintun|\bmeta\b'))
} catch {}
try {
 $v6 = @(Get-NetRoute -AddressFamily IPv6 -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq '::/0' })
 if ($v6.Count -eq 0) { $result.V6Safe = $true }
 else {
  $v6route = Find-NetRoute -RemoteIPAddress '2606:4700:4700::1111' | Where-Object { $_.DestinationPrefix } | Select-Object -Last 1
  $result.V6Safe = $result.TunRoute -and ($v6route.InterfaceIndex -eq $route.InterfaceIndex)
 }
} catch { $result.V6Safe = $false }
try {
 $claude = @(Get-Process -Name Claude -ErrorAction SilentlyContinue | Where-Object { $env:CLAUDE_SHIELD_TARGET -and $_.Path -ieq $env:CLAUDE_SHIELD_TARGET })
 $connections = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -eq 'Established' -and $claude.Id -contains $_.OwningProcess })
 if ($connections.Count -gt 40) { throw 'too many connections to classify' }
 foreach ($connection in $connections) {
  $remote = $connection.RemoteAddress
  if ($remote -eq '::1' -or $remote -like '127.*' -or $remote -eq '0.0.0.0' -or $remote -eq '::') { continue }
  $actual = Find-NetRoute -RemoteIPAddress $remote | Where-Object { $_.DestinationPrefix } | Select-Object -Last 1
  if (-not $actual) { throw 'route unavailable' }
  if (-not $result.TunRoute -or $actual.InterfaceIndex -ne $route.InterfaceIndex) { $result.Direct=$true }
 }
 $result.ConnectionsKnown=$true
} catch {}
try {
 $package = Get-AppxPackage | Where-Object { $_.Name -match '^Claude$|Anthropic.*Claude|Claude.*Anthropic' } | Select-Object -First 1
 if ($package) {
  $manifest = Get-AppxPackageManifest -Package $package.PackageFullName
  foreach ($application in $manifest.Package.Applications.Application) {
   $exe = Join-Path $package.InstallLocation $application.Executable
   if ((Split-Path $exe -Leaf) -ieq 'Claude.exe' -and (Test-Path -LiteralPath $exe)) {
    $result.ClaudePath=$exe; $result.LaunchId=$package.PackageFamilyName+'!'+$application.Id; break
   }
  }
 }
} catch {}
$result | ConvertTo-Json -Compress
