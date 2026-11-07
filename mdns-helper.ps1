# SPDX-License-Identifier: ISC
# Copyright (c) 2026 David Walther <david@clearbrookdistillery.com>
#
# mdns-helper.ps1 - the Windows side of wsl-dns-forward.
#
# Protocol: reads one hostname per line on stdin and writes "<hostname> <ipv4>"
# or "<hostname> -" on stdout.  The script is sent to powershell.exe by the
# daemon (-EncodedCommand), so it must stay plain ASCII.
#
# Raw mDNS A queries (with the QU bit, so the host replies by unicast) are sent
# from a socket bound to EACH real LAN address.  This avoids the interface
# Windows would pick for an unbound multicast socket, which on a machine
# running WSL2 is often the virtual WSL switch or an adapter with no link.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

function Get-LanIps {
  # Every usable IPv4 address except WSL's own virtual switches and link-local ones.
  # Adapters with a default gateway (the real LAN) come first.
  $found = @()
  foreach ($n in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
    if ($n.OperationalStatus -ne 'Up' -or $n.NetworkInterfaceType -eq 'Loopback' -or $n.NetworkInterfaceType -eq 'Tunnel') { continue }
    if ($n.Name -match '^vEthernet \((WSL|Default Switch)') { continue }
    $props = $n.GetIPProperties()
    $gw = @($props.GatewayAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' -and $_.Address.ToString() -ne '0.0.0.0' }).Count
    foreach ($a in $props.UnicastAddresses) {
      if ($a.Address.AddressFamily -ne 'InterNetwork' -or $a.Address.ToString() -like '169.254.*') { continue }
      $found += [pscustomobject]@{ Ip = $a.Address; Gw = $gw }
    }
  }
  $found | Sort-Object -Property Gw -Descending | ForEach-Object { $_.Ip }
}

function New-Query([string]$name) {
  $b = New-Object System.Collections.Generic.List[byte]
  $b.AddRange([byte[]](0,0, 0,0, 0,1, 0,0, 0,0, 0,0))
  foreach ($l in $name.Split('.')) { $b.Add([byte]$l.Length); $b.AddRange([Text.Encoding]::ASCII.GetBytes($l)) }
  $b.AddRange([byte[]](0, 0,1, 0x80,1))          # root, QTYPE=A, QCLASS=IN with the QU bit
  ,$b.ToArray()
}

# Decode a possibly compressed name starting at $i.  Returns @(name, index after the name) or $null.
function Read-Name($r, [int]$i) {
  $labels = @(); $next = -1; $hops = 0
  while ($true) {
    if ($i -ge $r.Length) { return $null }
    $c = $r[$i]
    if ($c -eq 0) { if ($next -lt 0) { $next = $i + 1 }; break }
    if (($c -band 0xC0) -eq 0xC0) {
      if ($i + 1 -ge $r.Length) { return $null }
      if ($next -lt 0) { $next = $i + 2 }
      $i = (($c -band 0x3F) * 256) + $r[$i + 1]
      $hops++
      if ($hops -gt 16) { return $null }
      continue
    }
    if (($c -band 0xC0) -ne 0 -or $i + 1 + $c -gt $r.Length) { return $null }
    $labels += [Text.Encoding]::ASCII.GetString($r, $i + 1, $c).ToLowerInvariant()
    $i += $c + 1
  }
  return @(($labels -join '.'), $next)
}

# The first A record in a reply whose owner name is exactly $name; $null if none.
function Get-NamedA($r, [string]$name) {
  if ($r.Length -lt 12) { return $null }
  if (($r[2] -band 0x80) -eq 0 -or ($r[3] -band 0x0F) -ne 0) { return $null }   # must be a successful response
  $qd = $r[4] * 256 + $r[5]
  $rrs = ($r[6] * 256 + $r[7]) + ($r[10] * 256 + $r[11])
  $i = 12
  for ($q = 0; $q -lt $qd; $q++) {
    $n = Read-Name $r $i; if (-not $n) { return $null }
    $i = $n[1] + 4
  }
  for ($k = 0; $k -lt $rrs; $k++) {
    $n = Read-Name $r $i; if (-not $n) { return $null }
    $i = $n[1]
    if ($i + 10 -gt $r.Length) { return $null }
    $type = $r[$i] * 256 + $r[$i + 1]
    $class = ($r[$i + 2] * 256 + $r[$i + 3]) -band 0x7FFF
    $len = $r[$i + 8] * 256 + $r[$i + 9]
    $i += 10
    if ($i + $len -gt $r.Length) { return $null }
    if ($type -eq 1 -and $class -eq 1 -and $len -eq 4 -and $n[0] -eq $name) {
      return "$($r[$i]).$($r[$i + 1]).$($r[$i + 2]).$($r[$i + 3])"
    }
    $i += $len
  }
  return $null
}

# Messages go to stderr (the daemon logs them): [ID] what, then why and try lines.  See wsl-dns-forward(8), DIAGNOSTICS.
function Write-Warn([string]$id, [string]$what, [string]$why, [string]$try) {
  $e = [Console]::Error
  $e.WriteLine("mdns-helper: [$id] $what")
  $e.WriteLine("    why: $why")
  $e.WriteLine("    try: $try")
  $e.WriteLine("    see: man 8 wsl-dns-forward, section DIAGNOSTICS, entry $id")
  $e.Flush()
}

function Resolve-Mdns([string]$name) {
  $q = New-Query $name
  if (-not (Get-LanIps)) { Write-Warn 'W06' "no usable LAN address for $name; trying the Windows resolver instead" 'Windows has no connected network adapter with an IPv4 address (Wi-Fi or Ethernet down, or only a VPN or virtual adapter)' 'connect to the network and try again; in PowerShell, run: Get-NetIPAddress -AddressFamily IPv4'; return $null }
  for ($round = 0; $round -lt 3; $round++) {
    foreach ($ip in (Get-LanIps)) {
      $u = $null
      try {
        $u = New-Object Net.Sockets.UdpClient((New-Object Net.IPEndPoint($ip, 0)))
        $u.Client.ReceiveTimeout = 400
        [void]$u.Send($q, $q.Length, '224.0.0.251', 5353)
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $stop = [Diagnostics.Stopwatch]::StartNew()
        while ($stop.ElapsedMilliseconds -lt 400) {
          $r = $u.Receive([ref]$ep)
          $a = Get-NamedA $r $name
          if ($a) { return $a }
        }
      } catch {} finally { if ($u) { $u.Close() } }
    }
  }
  return $null
}

while (($line = [Console]::In.ReadLine()) -ne $null) {
  $name = $line.Trim().ToLowerInvariant()
  if (-not $name) { continue }
  if ($name.Length -gt 253 -or $name -notmatch '^[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63})*\.local$') {
    [Console]::Out.WriteLine('invalid.local -'); [Console]::Out.Flush(); continue
  }
  $ip = Resolve-Mdns $name
  if (-not $ip) {
    Write-Warn 'W15' "no mDNS reply for $name; trying the Windows resolver instead" 'the other computer may be off, asleep or on another network, the name may be misspelled, or a firewall blocks UDP port 5353' "from Windows, run: ping $name   If that fails too, the problem is the network, not this daemon"
    try { $ip = (Resolve-DnsName $name -Type A -ErrorAction Stop | Where-Object Type -eq 'A' | Select-Object -First 1).IPAddress } catch {}
  }
  [Console]::Out.WriteLine("$name $(if ($ip) { $ip } else { '-' })")
  [Console]::Out.Flush()
}
