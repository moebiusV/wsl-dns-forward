# SPDX-License-Identifier: ISC
# Copyright (c) 2026 David Walther <david@clearbrookdistillery.com>
#
# mdns-helper.ps1 - the Windows side of wsl-dns-forward.
#
# Protocol: reads one request per line on stdin, "<hostname> [4|46]" (4 = IPv4 only, 46 = IPv4 and IPv6, the
# default), and writes "<hostname> <ipv4>|- [<ipv6>[,<ipv6>...]]" on stdout.  The script is sent to powershell.exe by the
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

function New-Query([string]$name, [byte]$qtype) {
  $b = New-Object System.Collections.Generic.List[byte]
  $b.AddRange([byte[]](0,0, 0,0, 0,1, 0,0, 0,0, 0,0))
  foreach ($l in $name.Split('.')) { $b.Add([byte]$l.Length); $b.AddRange([Text.Encoding]::ASCII.GetBytes($l)) }
  $b.AddRange([byte[]](0, 0,$qtype, 0x80,1))      # root, QTYPE (1 = A, 28 = AAAA), QCLASS=IN with the QU bit
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

# Add the A and AAAA records whose owner name is exactly $name to $acc (v4 = first IPv4, v6 = up to 4 IPv6).
# Link-local, multicast, loopback and IPv4-mapped IPv6 addresses are skipped: they cannot be used from WSL.
function Add-NamedAddrs($r, [string]$name, $acc) {
  if ($r.Length -lt 12) { return }
  if (($r[2] -band 0x80) -eq 0 -or ($r[3] -band 0x0F) -ne 0) { return }   # must be a successful response
  $qd = $r[4] * 256 + $r[5]
  $rrs = ($r[6] * 256 + $r[7]) + ($r[10] * 256 + $r[11])
  $i = 12
  for ($q = 0; $q -lt $qd; $q++) {
    $n = Read-Name $r $i; if (-not $n) { return }
    $i = $n[1] + 4
  }
  for ($k = 0; $k -lt $rrs; $k++) {
    $n = Read-Name $r $i; if (-not $n) { return }
    $i = $n[1]
    if ($i + 10 -gt $r.Length) { return }
    $type = $r[$i] * 256 + $r[$i + 1]
    $class = ($r[$i + 2] * 256 + $r[$i + 3]) -band 0x7FFF
    $len = $r[$i + 8] * 256 + $r[$i + 9]
    $i += 10
    if ($i + $len -gt $r.Length) { return }
    if ($class -eq 1 -and $n[0] -eq $name) {
      if ($type -eq 1 -and $len -eq 4 -and -not $acc.v4) {
        $acc.v4 = "$($r[$i]).$($r[$i + 1]).$($r[$i + 2]).$($r[$i + 3])"
      } elseif ($type -eq 28 -and $len -eq 16 -and $acc.v6.Count -lt 4) {
        $ip6 = [Net.IPAddress]::new([byte[]]$r[$i..($i + 15)])
        if (-not ($ip6.IsIPv6LinkLocal -or $ip6.IsIPv6Multicast -or $ip6.IsIPv6SiteLocal -or $ip6.IsIPv4MappedToIPv6 -or [Net.IPAddress]::IsLoopback($ip6) -or $ip6.Equals([Net.IPAddress]::IPv6None) -or $ip6.Equals([Net.IPAddress]::IPv6Any))) {
          $text = $ip6.ToString()
          if ($acc.v6 -notcontains $text) { [void]$acc.v6.Add($text) }
        }
      }
    }
    $i += $len
  }
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

function Resolve-Mdns([string]$name, [bool]$want6) {
  $q4 = New-Query $name 1
  $q6 = if ($want6) { New-Query $name 28 }
  if (-not (Get-LanIps)) { Write-Warn 'W06' "no usable LAN address for $name; trying the Windows resolver instead" 'Windows has no connected network adapter with an IPv4 address (Wi-Fi or Ethernet down, or only a VPN or virtual adapter)' 'connect to the network and try again; in PowerShell, run: Get-NetIPAddress -AddressFamily IPv4'; return $null }
  for ($round = 0; $round -lt 3; $round++) {
    foreach ($ip in (Get-LanIps)) {
      $u = $null
      $acc = @{ v4 = $null; v6 = (New-Object System.Collections.ArrayList) }
      try {
        $u = New-Object Net.Sockets.UdpClient((New-Object Net.IPEndPoint($ip, 0)))
        $u.Client.ReceiveTimeout = 400
        [void]$u.Send($q4, $q4.Length, '224.0.0.251', 5353)
        if ($want6) { [void]$u.Send($q6, $q6.Length, '224.0.0.251', 5353) }
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $stop = [Diagnostics.Stopwatch]::StartNew()
        while ($stop.ElapsedMilliseconds -lt 400) {
          $r = $u.Receive([ref]$ep)
          Add-NamedAddrs $r $name $acc
          if ($acc.v4 -and (-not $want6 -or $acc.v6.Count -gt 0)) { break }
          if ($acc.v4 -or $acc.v6.Count -gt 0) { $u.Client.ReceiveTimeout = 150 }   # a short wait for the other family
        }
      } catch {} finally { if ($u) { $u.Close() } }
      if ($acc.v4 -or $acc.v6.Count -gt 0) { return $acc }
    }
  }
  return $null
}

while (($line = [Console]::In.ReadLine()) -ne $null) {
  $parts = @($line.Trim().ToLowerInvariant() -split '\s+' | Where-Object { $_ })
  if ($parts.Count -eq 0) { continue }
  $name = $parts[0]
  $want6 = ($parts.Count -lt 2 -or $parts[1] -eq '46')
  if ($name.Length -gt 253 -or $name -notmatch '^[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63})*\.local$') {
    [Console]::Out.WriteLine('invalid.local -'); [Console]::Out.Flush(); continue
  }
  $acc = Resolve-Mdns $name $want6
  if (-not $acc) {
    Write-Warn 'W15' "no mDNS reply for $name; trying the Windows resolver instead" 'the other computer may be off, asleep or on another network, the name may be misspelled, or a firewall blocks UDP port 5353' "from Windows, run: ping $name   If that fails too, the problem is the network, not this daemon"
    $acc = @{ v4 = $null; v6 = (New-Object System.Collections.ArrayList) }
    try { $acc.v4 = (Resolve-DnsName $name -Type A -ErrorAction Stop | Where-Object Type -eq 'A' | Select-Object -First 1).IPAddress } catch {}
    if ($want6) {
      try {
        Resolve-DnsName $name -Type AAAA -ErrorAction Stop | Where-Object Type -eq 'AAAA' | Select-Object -First 4 | ForEach-Object {
          $ip6 = [Net.IPAddress]::Parse($_.IPAddress)
          if (-not ($ip6.IsIPv6LinkLocal -or $ip6.IsIPv6Multicast -or $ip6.IsIPv6SiteLocal -or $ip6.IsIPv4MappedToIPv6 -or [Net.IPAddress]::IsLoopback($ip6))) { [void]$acc.v6.Add($ip6.ToString()) }
        }
      } catch {}
    }
  }
  $v4 = if ($acc.v4) { $acc.v4 } else { '-' }
  $line6 = if ($acc.v6.Count -gt 0) { ' ' + ($acc.v6 -join ',') } else { '' }
  [Console]::Out.WriteLine("$name $v4$line6")
  [Console]::Out.Flush()
}
