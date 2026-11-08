# wsl-dns-forward

[Index: All Projects](https://moebiusv.github.io/) | [github.com/moebiusV/wsl-dns-forward](https://github.com/moebiusV/wsl-dns-forward) | `git clone https://github.com/moebiusV/wsl-dns-forward`

Rendezvous (also called mDNS or Bonjour) lets computers, printers and other devices on a local network be
reached by a name ending in `.local`, such as `printer.local`, with no DNS server to set up.

Inside WSL2 on Windows 10, those names usually do not resolve. `wsl-dns-forward` is a small DNS server for
the loopback address that fixes this. It answers `.local` questions by asking Windows, which can see the
network, and passes every other question to the normal DNS server. Programs in WSL need no changes.

## The problem

WSL2 runs Linux on a private virtual network behind a NAT gateway. The multicast packets that mDNS uses never
leave that network, so Linux programs cannot discover `.local` names themselves. Windows 11 22H2 and later can
hand DNS lookups to Windows (the `dnsTunneling` setting). Windows 10 cannot: WSL reports
`wsl: DNS Tunneling is not supported`.

What happens instead is worse than a clean failure. Lookups pass through WSL's DNS proxy to Windows, and the
answer differs from one try to the next:

* an IPv4 address, and the connection works;
* only an IPv6 address, which WSL2 cannot route, giving `Network is unreachable`;
* nothing, giving `Could not resolve hostname`.

The cause is on the Windows side. When a program sends a multicast packet without choosing a network adapter,
Windows picks one itself. On a computer running WSL2 that is often the virtual WSL switch or an adapter with
no link, where nothing answers. Windows' own resolver (`Resolve-DnsName`, `ping name.local`) is affected in the
same way, and changing interface metrics does not reliably change the choice. A query sent from a socket bound
to the real network adapter is answered every time.

## How it works

```
  program in WSL2
        |  DNS question
        v
  127.0.0.1:53   wsl-dns-forward  (Linux, unprivileged user)
        |                    |
        | name.local         | any other name
        v                    v
  powershell.exe        upstream DNS server
  (Windows, started     (from /etc/resolv.conf, the WSL
   through WSL interop)  gateway, or the servers you give)
        |  mDNS question, sent from the real network adapter
        v
  224.0.0.251:5353  --->  the device called name.local
```

The Windows half is a short PowerShell script, `mdns-helper.ps1`, that stays running. For each name it sends
an mDNS query from a socket bound to each connected network adapter, so the query always leaves through a real
network, and it accepts a reply only if the reply names the host that was asked about.

The daemon also:

* answers IPv6 (AAAA) questions with real IPv6 addresses when the system can route IPv6 (WSL2 mirrored
  networking), and with an empty reply when it cannot (WSL2 NAT mode), so programs never receive an address
  they cannot reach;
* remembers the last good address of each name, and refreshes names before they expire;
* keeps one slow lookup from holding up the others.

Every option, fallback and diagnostic message is described in `man 8 wsl-dns-forward`.

## Requirements

* Windows 10 with WSL2 (Windows 10 version 1903 or later). Windows PowerShell 5.1 ships with Windows 10.
* WSL interop enabled, which is the default. Test it with `powershell.exe -NoProfile -Command 1`.
* A WSL release that honours the `[boot]` setting used below: WSL 0.67.6 or newer. Microsoft's documentation
  lists `[boot]` as Windows 11 only, but it works on Windows 10 with WSL 2.6.3. `wsl --version` shows the
  installed release and `wsl --update` upgrades it. Setup step 2 gives an alternative.
* To build from source: a C compiler, `make` and `awk` (the minimal SUSE container images lack it). The tests also need `dig` (package `dnsutils`, `bind-utils`
  or `bind-tools`). Building from a git checkout also needs `autoconf` and `automake`.

Windows 11 is covered in "Windows 11" and "Upgrading from Windows 10 to Windows 11" below.

## Tested distributions

Every distribution in `wsl --list --online` was checked, plus Alpine, which can be imported with `wsl --import`.
The table records the results for the 1.0.0 release tarball. Each distribution built it in its official
container image: `./configure`, `make`, `make check` (unit tests, fuzz-corpus replay and an integration
test) and `make install`, with zero compiler warnings. The first five rows also have a native package that was
built and tested. Two entries were not built separately: eLxr (Debian based, with no public container image)
and SUSE Linux Enterprise 15 SP6 (the SP7 image has the same code base). The tests ran in container images, not
inside WSL itself.

| Distribution | WSL name | Package | Native package | Source build, tests, install | Compiler |
| --- | --- | --- | --- | --- | --- |
| Ubuntu 26.04 LTS | `Ubuntu-26.04` | `.deb` | built and installed, no lintian errors | passed | GCC 15.2.0 |
| Fedora 45 | `FedoraLinux-45` | `.rpm` | built, all tests pass | passed | GCC 16.2.1 |
| openSUSE Tumbleweed | `openSUSE-Tumbleweed` | `.rpm` (SUSE spec) | built, all tests pass | passed | GCC 16.2.1 |
| Arch Linux | `archlinux` | `PKGBUILD` | built, all tests pass | passed | GCC 16.2.1 |
| Alpine Linux (not in the WSL list; `wsl --import`) | `-` | `APKBUILD` | built, all tests pass | passed | GCC 15.2.0 |
| Ubuntu 24.04 LTS | `Ubuntu-24.04` | `.deb` | recipe provided | passed | GCC 13.3.0 |
| Ubuntu 22.04 LTS | `Ubuntu-22.04` | `.deb` | recipe provided | passed | GCC 11.4.0 |
| Debian GNU/Linux | `Debian` | `.deb` | recipe provided | passed | GCC 14.2.0 |
| Kali Linux | `kali-linux` | `.deb` | recipe provided | passed | GCC 16.2.0 |
| eLxr 12 (Debian based, no public container image) | `eLxr` | `.deb` | recipe provided | not separately built | - |
| Fedora 44 | `FedoraLinux-44` | `.rpm` | recipe provided | passed | GCC 16.2.1 |
| Rocky Linux Plus 9 | `RLCPlus-9` | `.rpm` | recipe provided | passed | GCC 11.5.0 |
| Rocky Linux Plus 10 | `RLCPlus-10` | `.rpm` | recipe provided | passed | GCC 14.3.1 |
| AlmaLinux 8 | `AlmaLinux-8` | `.rpm` | recipe provided | passed | GCC 8.5.0 |
| AlmaLinux 9 | `AlmaLinux-9` | `.rpm` | recipe provided | passed | GCC 11.5.0 |
| AlmaLinux 10 | `AlmaLinux-10` | `.rpm` | recipe provided | passed | GCC 14.3.1 |
| AlmaLinux Kitten 10 | `AlmaLinux-Kitten-10` | `.rpm` | recipe provided | passed | GCC 14.4.1 |
| Oracle Linux 7.9 | `OracleLinux_7_9` | `.rpm` | recipe provided (source build tested) | passed | GCC 4.8.5 |
| Oracle Linux 8.10 | `OracleLinux_8_10` | `.rpm` | recipe provided | passed | GCC 8.5.0 |
| Oracle Linux 9.5 | `OracleLinux_9_5` | `.rpm` | recipe provided | passed | GCC 11.5.0 |
| openSUSE Leap 16.1 | `openSUSE-Leap-16.1` | `.rpm` (SUSE spec) | recipe provided | passed | GCC 15.3.0 |
| SUSE Linux Enterprise 16.0 | `SUSE-Linux-Enterprise-16.0` | `.rpm` (SUSE spec) | recipe provided | passed | GCC 15.3.0 |
| SUSE Linux Enterprise 15 SP7 | `SUSE-Linux-Enterprise-15-SP7` | `.rpm` (SUSE spec) | recipe provided | passed | GCC 7.5.0 |
| SUSE Linux Enterprise 15 SP6 (same code base as SP7) | `SUSE-Linux-Enterprise-15-SP6` | `.rpm` (SUSE spec) | recipe provided | not separately built | - |

Oracle Linux 7.9, with GCC 4.8.5, is the oldest toolchain tested. The Debian, Fedora, openSUSE, Arch and Alpine
packages are installed with the commands in `README.distributions`.

## Installation

### From a release tarball

```sh
tar xzf wsl-dns-forward-1.1.0.tar.gz
cd wsl-dns-forward-1.1.0
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make
make check
sudo make install
```

From a git checkout (`git clone https://github.com/moebiusV/wsl-dns-forward`), run `autoreconf -i` before
`./configure`.

If `powershell.exe` is not under `/mnt/c/Windows/...` on your system, give its path at build time with
`./configure --with-powershell=/path/to/powershell.exe`, or at run time with `-w`.

### From packages

Packaging files for Debian and Ubuntu, Alpine, Arch, Fedora and the Red Hat family, and openSUSE and SUSE are in
`packaging/`.
`README.distributions` gives the commands to build and install a package from the release tarball on your own
system, including inside a WSL2 distribution.

## Setup

Installing the program does not change `/etc/wsl.conf` or `/etc/resolv.conf`. Those steps are yours to take.

### 1. Try it without changing anything

```sh
sudo wsl-dns-forward -p 5353 &
dig @127.0.0.1 -p 5353 printer.local        # use a .local name that exists on your network
```

The answer section should show the device's IPv4 address. If it does not, see Troubleshooting. Stop the test
copy with `sudo kill %1`.

### 2. Start it whenever WSL starts

Put this in `/etc/wsl.conf`, creating the file if needed:

```ini
[network]
generateResolvConf = false

[boot]
command = /usr/sbin/wsl-dns-forward -D -P /run/wsl-dns-forward.pid
```

`generateResolvConf = false` stops WSL from rewriting `/etc/resolv.conf` at every start. Leave
`generateHosts` alone so WSL keeps maintaining `/etc/hosts`. The `[boot]` line starts the daemon in the
background as root. It opens port 53, then switches to the user `nobody`, and a supervisor process restarts it
if it ever dies.

If your distribution runs systemd (`systemd=true` under `[boot]`), use the unit file instead. Configure with
`--with-systemdsystemunitdir=/usr/lib/systemd/system`, then run `sudo systemctl enable --now wsl-dns-forward`.

If `pgrep -a wsl-dns-forward` shows nothing after step 4, your WSL ignores `[boot]`. Update it with
`wsl --update`, or start the daemon from Windows, for example from a Task Scheduler task that runs at logon:

```
wsl.exe -u root -e /usr/sbin/wsl-dns-forward -D -P /run/wsl-dns-forward.pid
```

### 3. Point the system at it

Put `127.0.0.1` first and keep your current nameservers after it. They are a safety net: if the daemon is ever
not running, programs fall back to them after a short delay. The resolver reads at most three `nameserver`
lines, so keep the list to three.

```sh
sudo cp /etc/resolv.conf /etc/resolv.conf.pre-wsl-dns-forward
{ echo "nameserver 127.0.0.1"; grep '^nameserver' /etc/resolv.conf.pre-wsl-dns-forward | head -2; } \
    | sudo tee /etc/resolv.conf.new >/dev/null
sudo mv -f /etc/resolv.conf.new /etc/resolv.conf
```

If `/etc/resolv.conf` is a symlink, the last command replaces it with a plain file, which is what is wanted.
Do not make the file immutable with `chattr +i`: it gains nothing once `generateResolvConf = false` is set, and
it blocks the edits described under "Upgrading".

### 4. Restart WSL and check

In Windows PowerShell or Command Prompt run `wsl --shutdown`, then open WSL again:

```sh
pgrep -a wsl-dns-forward                  # the daemon is running
getent ahosts printer.local                # an IPv4 address
ping -c1 printer.local
dig +short example.com                     # ordinary names still resolve
```

## How the setup survives upgrades

Windows, WSL and the network all change over time. The setup is arranged so that none of those changes needs
an edit on the Linux side:

* **No address is hard-coded.** With no `-u` option, the daemon finds its upstream DNS servers each time it
  starts, from the `nameserver` lines in `/etc/resolv.conf`, then the WSL default gateway, then
  `10.255.255.254` (the DNS tunnel of Windows 11 22H2 and later). It tries them in that order, remembers which
  one answered last, and tries that one first. A server that no longer exists costs one two-second delay, once.
* **The fallback nameservers are kept.** `/etc/resolv.conf` lists `127.0.0.1` and then the existing servers, so
  DNS keeps working during the moment the daemon restarts.
* **The Windows half looks at the network on every lookup.** It lists the connected adapters each time, so
  moving from Wi-Fi to Ethernet, joining a VPN, or a changed adapter name needs nothing. It skips only WSL's
  own virtual switches (`vEthernet (WSL...)` and `vEthernet (Default Switch)`), whose names are the same on
  Windows 10 and 11.
* **PowerShell is located twice.** The path chosen at build time is used first, then `powershell.exe` from
  `PATH`. Windows PowerShell 5.1 is present on every supported Windows release.
* **Failures heal.** If the Windows helper dies it is restarted with a growing delay. If the daemon itself
  dies, the supervisor restarts it. Neither loses the cache, which is also kept on disk.
* **Addresses are re-checked, not trusted.** A cached address is used for two minutes and refreshed in the
  background before it expires. After that the name is looked up again before it is answered, so a device
  whose address changed is never answered with the old one. The previous address is returned only when the
  lookup fails.
* **IPv6 is detected, not configured.** Every few seconds the daemon checks whether the system has a global
  IPv6 address and an IPv6 default route. If it does, as with WSL2 mirrored networking, `.local` AAAA
  questions are answered with the device's real IPv6 addresses. If not, as in WSL2 NAT mode, they get an empty
  answer and programs use IPv4. A change of networking mode, or an upgrade, switches behaviour by itself, and
  the log says which mode is in use.
* **The configuration lives in the Linux distribution.** `/etc/wsl.conf` and `/etc/resolv.conf` stay as they
  are across Windows upgrades and `wsl --update`. Nothing in them depends on a Windows or WSL version.
* **Nothing is changed behind your back.** Packages never edit `/etc/wsl.conf` or `/etc/resolv.conf`. The
  `.pre-wsl-dns-forward` copy of the original is yours to restore.
* **Problems explain themselves.** Each diagnostic names the cause and the fix, so an unexpected change shows
  up as a readable message in the log rather than as silence.

## Windows 11

Windows 11 22H2 and later has its own DNS tunneling (on by default) and an optional mirrored networking mode
with multicast support, so this program may not be needed there. If it is used, Microsoft's documentation
(https://learn.microsoft.com/en-us/windows/wsl/networking and
https://learn.microsoft.com/en-us/windows/wsl/wsl-config) points to these differences, and the program is
written to accommodate them:

* With DNS tunneling on, DNS from WSL goes to the virtual address `10.255.255.254`, and the WSL gateway no
  longer proxies DNS. The daemon does not depend on the gateway; see the first item above.
* In mirrored mode WSL shares Windows' loopback address, so port 53 must be free on the Windows side. It
  normally is. A clash is reported as `[E01]`. Mirrored mode also gives WSL IPv6 routing, so the daemon then
  returns IPv6 addresses for `.local` names as well.
* `[boot]` is supported.
* The Windows half is standard Windows PowerShell 5.1 and .NET sockets.

Windows 11 is not part of the test matrix. If something differs, the log says why (see Troubleshooting), and
`-u ADDRESS` always overrides the upstream choice.

## Upgrading from Windows 10 to Windows 11

A Windows upgrade keeps WSL distributions as they are, so nothing is reinstalled. The expected path:

1. **Upgrade Windows, then update WSL.** In Windows run `wsl --update`, then `wsl --shutdown`.
2. **Open WSL and check.**
   ```sh
   pgrep -a wsl-dns-forward         # running
   getent ahosts printer.local       # an IPv4 address
   dig +short example.com            # ordinary names resolve
   grep -E 'upstream|\[W|\[E' /var/log/wsl-dns-forward.log | tail
   ```
   The `upstream` lines show which servers the daemon found. With Windows 11's default settings,
   `10.255.255.254` is among them.
3. **Tidy the nameserver list when convenient.** A saved Windows 10 nameserver, such as the old WSL gateway
   address, may no longer exist. The first lookup afterwards waits two seconds and logs `[W07]`; after that the
   daemon skips that server. To remove even that delay, delete the dead `nameserver` lines from
   `/etc/resolv.conf` (keep `nameserver 127.0.0.1` first), or pass the right server with `-u`.
4. **Nothing else is needed.** `.local` names keep working because the Windows half uses the real network
   adapters, which exist on both systems.

Two Windows-side settings can matter:

* `dnsTunneling=false` in `%USERPROFILE%\.wslconfig` turns Windows 11's DNS tunnel off. The daemon works either
  way: with the tunnel off, the WSL gateway answers DNS again and is one of the servers it tries.
* `networkingMode=mirrored` shares the loopback address with Windows, as described above.

### Switching to WSL's own features

To let Windows 11 do this job itself, undo the setup so WSL manages DNS again:

```sh
sudo rm -f /etc/resolv.conf                       # WSL recreates it
sudo sed -i '/wsl-dns-forward/d' /etc/wsl.conf   # remove the [boot] command
sudo sed -i '/generateResolvConf/d' /etc/wsl.conf
```

Then, if you want multicast to reach Linux directly, put `networkingMode=mirrored` under `[wsl2]` in
`%USERPROFILE%\.wslconfig`, and run `wsl --shutdown`. Check with `getent ahosts printer.local`. If `.local`
names still fail, repeat Setup; nothing is lost by switching back.

## Troubleshooting

The daemon reports problems in plain words, with a likely cause and something to try. Messages go to the
terminal, or to `/var/log/wsl-dns-forward.log` when started with `-D`. Each has an ID such as `[E04]`, which
is explained in the DIAGNOSTICS section of `man 8 wsl-dns-forward`.

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `[E01] cannot listen` | Another program has port 53, or the daemon was not started as root | `ss -lunp 'sport = :53'`; stop the other program or a leftover copy |
| `[E04] cannot run powershell.exe` | WSL interop is off, or PowerShell is elsewhere | `powershell.exe -NoProfile -Command 1`; check `/etc/wsl.conf` has no `[interop] enabled=false`; use `-w` |
| `[W15]` or `[W06]` in the log | Windows could not find the name on the network | From Windows run `ping printer.local`. If that fails, the device is off, asleep or on another network |
| `[W07]` in the log | An upstream DNS server does not answer | `dig @ADDRESS example.com`; fix the `nameserver` lines or use `-u` |
| Daemon not running after a restart | WSL ignores the `[boot]` line | `wsl --update`, or start it from Windows as shown in Setup step 2 |
| `.local` fails though the daemon runs | `/etc/nsswitch.conf` has an `mdns` entry that ends the search early | Make the line `hosts: files dns`; remove `libnss-mdns` if it is not needed |
| Nothing resolves | `/etc/resolv.conf` points at the daemon and it is not running | `pgrep -a wsl-dns-forward`; read the log; run it without `-D` to see its messages |
| `Network is unreachable` on a `.local` name | The program was given an IPv6 address this system cannot route | The log line "IPv6 is not routable here" shows the daemon is withholding IPv6 addresses; if it says "routable" and connections still fail, check `ip -6 route` |
| Ordinary names are slow | The daemon is down and programs wait before trying the next nameserver | Start it, or see `[W07]` |

To watch the daemon work, run it in the foreground (`sudo wsl-dns-forward`) and query it from another
terminal. To run the Windows half by hand:

```sh
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(wslpath -w /usr/share/wsl-dns-forward/mdns-helper.ps1)"
```

Type a name such as `printer.local` and press Enter. It prints the name and the address, or a dash.

## Security notes

* mDNS has no authentication. Any machine on the network can claim any `.local` name, so a `.local` address is
  as trustworthy as the network it came from.
* The daemon listens on `127.0.0.1` only, so nothing outside the computer can query it.
* After opening port 53 it runs as an unprivileged user.
* Names passed to the Windows helper may contain only letters, digits, hyphens and underscores. Anything else
  is refused before it reaches PowerShell.
* An mDNS answer is accepted only if its owner name matches the name asked, and loopback, multicast and
  reserved addresses are discarded.
* An upstream reply is accepted only from the server asked, with the matching ID and question.
* The packet-handling code is covered by unit tests, an integration test and libFuzzer targets, and has been
  checked with AddressSanitizer, UndefinedBehaviorSanitizer, valgrind, cppcheck and the GCC and clang static
  analyzers.

## Limitations

* Only `A` and `AAAA` records are answered for `.local` names. Reverse lookups and service discovery (PTR, SRV, TXT)
  are not.
* Over TCP, one query is served per connection.
* Windows must allow `powershell.exe` to run. Locked-down managed machines may block it.

## Uninstall

```sh
sudo cp /etc/resolv.conf.pre-wsl-dns-forward /etc/resolv.conf   # the original nameservers
sudo sed -i '/wsl-dns-forward/d' /etc/wsl.conf                    # remove the [boot] command
sudo make uninstall                                                  # from the build directory
```

Remove `generateResolvConf = false` from `/etc/wsl.conf` if WSL should manage `/etc/resolv.conf` again, then
run `wsl --shutdown` in Windows.

## Development

```sh
autoreconf -i
./configure --enable-sanitizers      # AddressSanitizer and UBSan
make check                           # unit tests, fuzz corpus replay, integration test
make check-valgrind                  # the same under valgrind (configure without --enable-sanitizers)
CC=clang ./configure --enable-fuzzers && make fuzz_query fuzz_relay fuzz_helper
./fuzz_query -max_total_time=600 corpus_dir fuzz/corpus/query
```

`dns.c` holds all packet handling and does no I/O, which is what the fuzz targets exercise. `main.c` is the
event loop and process management, and `mdns-helper.ps1` is the Windows side.

## License

ISC. See `COPYING`. Copyright (c) 2026 David Walther.
