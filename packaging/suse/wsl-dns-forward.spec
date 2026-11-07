Name:           wsl-dns-forward
Version:        1.0.0
Release:        0
Summary:        Local DNS forwarder that makes .local (mDNS) names work inside WSL2
License:        ISC
Group:          Productivity/Networking/DNS/Servers
URL:            https://github.com/moebiusV/wsl-dns-forward
Source0:        %{url}/releases/download/v%{version}/%{name}-%{version}.tar.gz
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  gawk
BuildRequires:  bind-utils
BuildRequires:  systemd-rpm-macros

%description
Rendezvous (mDNS, Bonjour) lets devices on a local network be reached by names
ending in .local. WSL2 cannot see the multicast traffic mDNS uses, and Windows
10 has no DNS tunneling to hand the lookups to Windows.

wsl-dns-forward is a small DNS server for the loopback address. It answers
.local questions through a helper running in Windows PowerShell, which sends
the mDNS query from the real network adapter, and passes every other question
to the normal upstream DNS server.

Installing the package does not change /etc/wsl.conf or /etc/resolv.conf. See
%{_docdir}/%{name}/README.md for the setup steps.

%prep
%autosetup

%build
%configure --with-systemdsystemunitdir=%{_unitdir}
%make_build

%install
%make_install

%check
make check

%files
%license COPYING
%doc README.md NEWS
%{_sbindir}/%{name}
%{_datadir}/%{name}/
%{_unitdir}/%{name}.service
%{_mandir}/man8/%{name}.8%{?ext_man}

%changelog
