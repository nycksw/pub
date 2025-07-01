# [DOM XSS: `document.write` Sink Using Source `location.search`](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink)

Vulnerable snippet:

```html
<script>
  function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
  }
  var query = (new URLSearchParams(window.location.search)).get('search');
  if(query) {
    trackSearch(query);
  }
</script>
```

[DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader) solves this one in a few seconds:

![](_/psa-dom-xss-in-document.write-sink-using-source-location.search-20250610-2.png)

![](_/psa-dom-xss-in-document.write-sink-using-source-location.search-20250610-1.png)

Clicking "Exploit" solves the lab.