# RPM spec file for aproxy

%define name aproxy
%define version ${VERSION}
%define release 1
%define _arch %{ARCH}
%define debug_package %{nil}
%define __strip /bin/true

Name:           aproxy
Release:        1%{?dist}
Version:        %{VERSION}
Summary:        Transparent proxy for HTTP and HTTPS/TLS connections
License:        ASL 2.0

%description
Aproxy is a transparent proxy for HTTP and HTTPS/TLS connections. By pre-reading the Host header in HTTP requests and the SNI in TLS client hellos, it forwards HTTP proxy requests with the hostname, therefore, complies with HTTP proxies requiring destination hostname for auditing or access control.

%install
# Create destination directory for the binary
install -d %{buildroot}/usr/bin
# Copy the built binary to the destination directory
install -m 755 %{_topdir}/../out/aproxy.%{ARCH} %{buildroot}/usr/bin/aproxy
# Copy the systemd unit file to the destination directory
install -d  %{buildroot}/usr/lib/systemd/system/
install -m 644 %{_topdir}/../aproxy.service %{buildroot}/usr/lib/systemd/system/
# Create the config.env file
install -d %{buildroot}/etc/aproxy
echo "PROXY_URL=127.0.0.1:3128" > %{buildroot}/etc/aproxy/config.env

%files
# Installed binary
/usr/bin/aproxy
# Systemd unit file
/usr/lib/systemd/system/aproxy.service
# Config file
/etc/aproxy/*

%post
%systemd_post aproxy.service

%preun
%systemd_preun aproxy.service

%postun
%systemd_postun_with_restart aproxy.service
