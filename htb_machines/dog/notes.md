# DOG Machine - Easy

## Enumeration
1. **Nmap Scan**:
   - Found open ports: **80 (HTTP)** and **22 (SSH)**.

2. **Gobuster Scan**:
   - Discovered a `.git` directory.

## Exploitation
1. **Dumping the .git Directory**:
   - Used `git_dumper` to dump the `.git` directory.
   - Found a password in `settings.php`.

2. **Identifying Potential Users**:
   - Found a user: `tiffany` (admin).

3. **CMS Vulnerability**:
   - The CMS was vulnerable to a known CVE.
   - Added a malicious module to gain a backdoor.

4. **SSH Access**:
   - Found users in `/etc/passwd`.
   - Used the password from `settings.php` to SSH into the machine as one of the users.

## Privilege Escalation
1. **Sudo Permissions**:
   - Checked with `sudo -l` and found a PHP script using the `eval()` function.

2. **Payload Execution**:
   - Used the following payload to escalate privileges:
     ```bash
     sudo /usr/local/bin/bee --root=/var/www/html eval "echo shell_exec('su root -');"
     ```

## Notes
- The `eval()` function in the PHP script was the key to privilege escalation.
- Always check for `.git` directories during enumeration as they can reveal sensitive information.