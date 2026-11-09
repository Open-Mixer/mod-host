# The RPMs of the FreeMixer fork of mod-host, built from this tree as the DEBs of debian/ are, at the
# same version. The fork carries the upstream pull requests as commits (README.md); no patch is applied here.
Name: mod-host
Version: 0.10.11
Release: 1%{?dist}
License: GPL-3.0-or-later
Summary: LV2 host for JACK, controllable over a socket or the command line
URL: https://github.com/FreeMixer/mod-host
ExclusiveArch: x86_64 aarch64

Source0: %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires: gcc
BuildRequires: make
BuildRequires: python3
BuildRequires: readline-devel
BuildRequires: fftw-devel
BuildRequires: pkgconfig(jack)
BuildRequires: pkgconfig(lv2)
BuildRequires: pkgconfig(lilv-0)
BuildRequires: systemd-rpm-macros

%{?systemd_requires}
Requires: lilv
Requires: %{name}-protocol%{?_isa} = %{version}-%{release}

%description
mod-host loads LV2 plugins as JACK clients and is driven over a TCP socket or
an interactive command line. This build is the FreeMixer fork, which carries
its changes as pull requests to mod-audio/mod-host.

%package protocol
Summary: mod-host socket server, line protocol and command dispatch

%description protocol
libmod-host-protocol, the socket server, line protocol and command dispatch of
mod-host without any plugin format behind them, for hosts that answer the
mod-host protocol with a plugin backend of their own.

%package protocol-devel
Summary: Headers and pkg-config file for the mod-host protocol library
Requires: %{name}-protocol%{?_isa} = %{version}-%{release}

%description protocol-devel
Headers, the pkg-config file and the backend scenarios of libmod-host-protocol.

%prep
%autosetup -p1

%build
%set_build_flags
# the Makefile strips with -s; the debuginfo split needs the symbols
%make_build PREFIX=%{_prefix} LIBDIR=%{_libdir} LDFLAGS="%{build_ldflags}" VERSION=%{version} all
%make_build PREFIX=%{_prefix} LIBDIR=%{_libdir} LDFLAGS="%{build_ldflags}" VERSION=%{version} lib

%install
%make_install PREFIX=%{_prefix} LIBDIR=%{_libdir} MANDIR=%{_mandir}/man1 LDFLAGS="%{build_ldflags}" VERSION=%{version} install-lib
install -D -m 644 packaging/%{name}.service %{buildroot}%{_unitdir}/%{name}.service
install -D -m 644 packaging/%{name}.user.service %{buildroot}%{_userunitdir}/%{name}.service
install -D -m 644 packaging/%{name}.sysusers %{buildroot}%{_sysusersdir}/%{name}.conf

%check
./mod-host -V | grep -F 'version: %{version}'
make PREFIX=%{_prefix} LIBDIR=%{_libdir} LDFLAGS="%{build_ldflags}" VERSION=%{version} test-protocol test-protocol-commands

%files
%license COPYING
%doc CHANGELOG README.md
%{_bindir}/mod-host
%{_libdir}/jack/*.so
%{_mandir}/man1/mod-host.1*
%{_unitdir}/%{name}.service
%{_userunitdir}/%{name}.service
%{_sysusersdir}/%{name}.conf

%files protocol
%license COPYING
%{_libdir}/libmod-host-protocol.so.0*

%files protocol-devel
%{_libdir}/libmod-host-protocol.so
%{_includedir}/mod-host/
%{_libdir}/pkgconfig/mod-host-protocol.pc
%{_datadir}/mod-host/

%changelog
