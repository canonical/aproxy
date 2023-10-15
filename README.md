# aproxy - transparent proxy for HTTP and HTTPS/TLS

Aproxy is a transparent proxy for HTTP and HTTPS/TLS connections. By pre-reading
the Host header in HTTP requests and the SNI in TLS client hellos, it forwards
HTTP proxy requests with the hostname, therefore, complies with HTTP proxies
requiring destination hostname for auditing or access control.

## Usage

Install aproxy using snap, and configure the upstream http proxy.

```bash
sudo snap install aproxy --edge
sudo snap set aproxy proxy=squid.internal:3128
```

Create the following nftables rules to redirect outbound traffic to aproxy on
the same machine. Please note that aproxy for now only works with IPv4,
supporting only HTTP on port 80 and HTTPS/TLS on port 443.

```bash
nft -f - << EOF
define default-ip = $(ip route get $(ip route show 0.0.0.0/0 | grep -oP 'via \K\S+') | grep -oP 'src \K\S+')
define private-ips = { 10.0.0.0/8, 127.0.0.1/8, 172.16.0.0/12, 192.168.0.0/16 }
table ip aproxy
flush table ip aproxy
table ip aproxy {
        chain prerouting {
                type nat hook prerouting priority dstnat; policy accept;
                ip daddr != \$private-ips tcp dport { 80, 443 } counter dnat to \$default-ip:8443
        }

        chain output {
                type nat hook output priority -100; policy accept;
                ip daddr != \$private-ips tcp dport { 80, 443 } counter dnat to \$default-ip:8443
        }
}
EOF
```

You can inspect the access logs of aproxy using:

```bash
sudo snap logs aproxy.aproxy
```
