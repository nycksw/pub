# PortSwigger: [`SameSite=Lax` Bypass via Method Override](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-lax-bypass-via-method-override)

Modern browsers default to `SameSite=Lax` for cookies, making some [CSRF exploits](psa-csrf-token-tied-to-non-session-cookie-20250603.md) more difficult.

This exploit uses request-method confusion to allow the cookie to be sent via GET while still appearing as a POST request to the handler:

![](_/psa-samesite-lax-bypass-20250603-1.png)

This is dependent on the target framework allowing the request-type override inside of the form.