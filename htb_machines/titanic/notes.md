# Initial Foothold

1. **Nmap Scan**:
   - Discovered open ports: **HTTP** and **SSH**.

2. **Website Analysis**:
   - Found a booking URL on the website.
   - After making a reservation, noticed that the web server creates a route with the parameter `ticket` pointing to a file.

3. **Vulnerability**:
   - The `ticket` parameter is vulnerable to **Local File Inclusion (LFI)**.