## CL.TE detection

Send the following request which includes both a `Content-Length` header and `Transfer-Encoding: chunked`:

```http
POST / HTTP/1.1\r\n
Host: HOST\r\n
Content-Length: 6\r\n
Transfer-Encoding: chunked\r\n
Content-Type: application/x-www-form-urlencoded\r\n
\r\n
3\r\n
abc\r\n
X\r\n
```

### Explanation

When a front-end/proxy and a back-end server disagree about which framing method to use, request smuggling can occur. If the front-end honors `Content-Length` and the back-end expects chunked framing, the back-end may receive an incomplete chunked stream.

Example: the front-end reads exactly the number of bytes from `Content-Length` and forwards them. The back-end, parsing chunked data, may read a valid chunk (`3\r\nabc\r\n`) and then interpret the remaining bytes (e.g. `X\r\n`) as the next chunk-size line. Because `X` is not a valid chunk-size, the back-end waits for more data and may hang or time out.

### Example: how the attack can arise

Another payload variant demonstrates how leftover bytes become the start of the next request:

```http
POST / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
Content-Length: 6\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
G
```

If the front-end uses `Content-Length` it will forward the declared number of bytes and include the `G`. The back-end, interpreting the body as chunked, reads the `0\r\n\r\n` sequence (end of chunked body) and then sees `G` as the start of the next request (for example the first byte of the next request line). In other words, `G` becomes the first byte of the next request the back-end processes, which allows an attacker to smuggle bytes into a subsequent request.

## TE.CL detection
