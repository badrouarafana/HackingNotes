# NMAP

## Syntax

| Option                | Description           |
|-----------------------|-----------------------|
| -sS                   | SYN                   |
| -sT                   | SYN-ACK               |
| -Pn                   | Disable ping          |
| --disable-arp-ping    | Disable ARP ping      |
| -n                    | Disable DNS resolution|
| -sU                   | UDP port              |
|--packet-trace         | packet trace          |

Scan a range of ip

    sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
-sn : to disable port scanning

so scan for vulns add `-script vuln`

## Performance
example to change the rtt 
    
    nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms

--initial-rtt-timeout 50ms:	Sets the specified time value as initial RTT timeout.

--max-rtt-timeout 100ms:	Sets the specified time value as maximum RTT timeout.


    nmap 10.129.2.0/24 -F -oN tnet.minrate300 --min-rate 300

--min-rate 300	Sets the minimum number of packets to be sent per second.

-F	Scans top 100 ports.

## Firewall and IDS/IPS Evasion

To try bypass the firewall aim for `-sA` the host in likely to respond with a `RST` flag.

Decoy : to change the ip addresses on random : `-D RND:5` 

We can change source sport for example `--source-port X`
