
# ZAP Scanning Report

Generated on Tue, 30 Mar 2021 13:22:00


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 1 |
| Medium | 3 |
| Low | 5 |
| Informational | 5 |

## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- | 
| PII Disclosure | High | 1 | 
| CSP: style-src unsafe-inline | Medium | 2 | 
| CSP: Wildcard Directive | Medium | 2 | 
| Vulnerable JS Library | Medium | 1 | 
| CSP: Notices | Low | 2 | 
| Dangerous JS Functions | Low | 3 | 
| Feature Policy Header Not Set | Low | 5 | 
| Incomplete or No Cache-control and Pragma HTTP Header Set | Low | 5 | 
| Strict-Transport-Security Header Not Set | Low | 2 | 
| Base64 Disclosure | Informational | 3 | 
| Information Disclosure - Suspicious Comments | Informational | 11 | 
| Modern Web Application | Informational | 4 | 
| Storable and Cacheable Content | Informational | 11 | 
| Timestamp Disclosure - Unix | Informational | 949 | 

## Alert Detail


  
  
  
  
### PII Disclosure
##### High (High)
  
  
  
  
#### Description
<p>The response contains Personally Identifiable Information, such as CC number, SSN and similar sensitive data.</p>
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `4242424242424242`
  
  
  
  
Instances: 1
  
### Solution
<p></p>
  
### Other information
<p>Credit Card Type detected: Visa</p><p>Bank Identification Number: 424242</p><p>Brand: VISA</p><p>Category: </p><p>Issuer: </p>
  
### Reference
* 

  
#### CWE Id : 359
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### CSP: style-src unsafe-inline
##### Medium (Medium)
  
  
  
  
#### Description
<p>style-src includes unsafe-inline.</p>
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/](https://kelrisks.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Content-Security-Policy`
  
  
  * Evidence: `default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://haveibeenpwned.com https://www.gravatar.com; child-src 'self' https://*.duosecurity.com; frame-src 'self' https://*.duosecurity.com; connect-src 'self' wss://bitwarden.ksuto.fr https://api.pwnedpasswords.com https://twofactorauth.org; object-src 'self' blob:;`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr](https://kelrisks.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Parameter: `Content-Security-Policy`
  
  
  * Evidence: `default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://haveibeenpwned.com https://www.gravatar.com; child-src 'self' https://*.duosecurity.com; frame-src 'self' https://*.duosecurity.com; connect-src 'self' wss://bitwarden.ksuto.fr https://api.pwnedpasswords.com https://twofactorauth.org; object-src 'self' blob:;`
  
  
  
  
Instances: 2
  
### Solution
<p>Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.</p>
  
### Reference
* http://www.w3.org/TR/CSP2/
* http://www.w3.org/TR/CSP/
* http://caniuse.com/#search=content+security+policy
* http://content-security-policy.com/
* https://github.com/shapesecurity/salvation
* https://developers.google.com/web/fundamentals/security/csp#policy_applies_to_a_wide_variety_of_resources

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### CSP: Wildcard Directive
##### Medium (Medium)
  
  
  
  
#### Description
<p>The following directives either allow wildcard sources (or ancestors), are not defined, or are overly broadly defined: </p><p>frame-ancestors, form-action</p><p></p><p>The directive(s): frame-ancestors, form-action are among the directives that do not fallback to default-src, missing/excluding them is the same as allowing anything.</p>
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/](https://kelrisks.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Content-Security-Policy`
  
  
  * Evidence: `default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://haveibeenpwned.com https://www.gravatar.com; child-src 'self' https://*.duosecurity.com; frame-src 'self' https://*.duosecurity.com; connect-src 'self' wss://bitwarden.ksuto.fr https://api.pwnedpasswords.com https://twofactorauth.org; object-src 'self' blob:;`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr](https://kelrisks.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Parameter: `Content-Security-Policy`
  
  
  * Evidence: `default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://haveibeenpwned.com https://www.gravatar.com; child-src 'self' https://*.duosecurity.com; frame-src 'self' https://*.duosecurity.com; connect-src 'self' wss://bitwarden.ksuto.fr https://api.pwnedpasswords.com https://twofactorauth.org; object-src 'self' blob:;`
  
  
  
  
Instances: 2
  
### Solution
<p>Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.</p>
  
### Reference
* http://www.w3.org/TR/CSP2/
* http://www.w3.org/TR/CSP/
* http://caniuse.com/#search=content+security+policy
* http://content-security-policy.com/
* https://github.com/shapesecurity/salvation
* https://developers.google.com/web/fundamentals/security/csp#policy_applies_to_a_wide_variety_of_resources

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Vulnerable JS Library
##### Medium (Medium)
  
  
  
  
#### Description
<p>The identified library jquery, version 3.4.1 is vulnerable.</p>
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `* jQuery JavaScript Library v3.4.1`
  
  
  
  
Instances: 1
  
### Solution
<p>Please upgrade to the latest version of jquery.</p>
  
### Other information
<p>CVE-2020-11023</p><p>CVE-2020-11022</p><p></p>
  
### Reference
* https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/
* 

  
#### CWE Id : 829
  
#### Source ID : 3

  
  
  
  
### CSP: Notices
##### Low (Medium)
  
  
  
  
#### Description
<p>Warnings:</p><p>1:129: The child-src directive is deprecated as of CSP level 3. Authors who wish to regulate nested browsing contexts and workers SHOULD use the frame-src and worker-src directives, respectively.</p><p></p>
  
  
  
* URL: [https://kelrisks.beta.gouv.fr](https://kelrisks.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Parameter: `Content-Security-Policy`
  
  
  * Evidence: `default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://haveibeenpwned.com https://www.gravatar.com; child-src 'self' https://*.duosecurity.com; frame-src 'self' https://*.duosecurity.com; connect-src 'self' wss://bitwarden.ksuto.fr https://api.pwnedpasswords.com https://twofactorauth.org; object-src 'self' blob:;`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/](https://kelrisks.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Content-Security-Policy`
  
  
  * Evidence: `default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://haveibeenpwned.com https://www.gravatar.com; child-src 'self' https://*.duosecurity.com; frame-src 'self' https://*.duosecurity.com; connect-src 'self' wss://bitwarden.ksuto.fr https://api.pwnedpasswords.com https://twofactorauth.org; object-src 'self' blob:;`
  
  
  
  
Instances: 2
  
### Solution
<p>Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.</p>
  
### Reference
* http://www.w3.org/TR/CSP2/
* http://www.w3.org/TR/CSP/
* http://caniuse.com/#search=content+security+policy
* http://content-security-policy.com/
* https://github.com/shapesecurity/salvation
* https://developers.google.com/web/fundamentals/security/csp#policy_applies_to_a_wide_variety_of_resources

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Dangerous JS Functions
##### Low (Low)
  
  
  
  
#### Description
<p>A dangerous JS function seems to be in use that would leave the site vulnerable.</p>
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `bypassSecurityTrustHtml`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/polyfills.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/polyfills.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `eVal`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `bypassSecurityTrustResourceUrl`
  
  
  
  
Instances: 3
  
### Solution
<p>See the references for security advice on the use of these functions.</p>
  
### Reference
* https://angular.io/guide/security

  
#### CWE Id : 749
  
#### Source ID : 3

  
  
  
  
### Feature Policy Header Not Set
##### Low (Medium)
  
  
  
  
#### Description
<p>Feature Policy Header is an added layer of security that helps to restrict from unauthorized access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting or specifying the features of the browsers can be used by the web resources. Feature Policy provides a set of standard HTTP headers that allow website owners to limit which features of browsers can be used by the page such as camera, microphone, location, full screen etc.</p>
  
  
  
* URL: [https://kelrisks.beta.gouv.fr](https://kelrisks.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/](https://kelrisks.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/polyfills.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/polyfills.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  
  
Instances: 5
  
### Solution
<p>Ensure that your web server, application server, load balancer, etc. is configured to set the Feature-Policy header.</p>
  
### Reference
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy
* https://developers.google.com/web/updates/2018/06/feature-policy
* https://scotthelme.co.uk/a-new-security-header-feature-policy/
* https://w3c.github.io/webappsec-feature-policy/
* https://www.smashingmagazine.com/2018/12/feature-policy/

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Incomplete or No Cache-control and Pragma HTTP Header Set
##### Low (Medium)
  
  
  
  
#### Description
<p>The cache-control and pragma HTTP header have not been set properly or are missing allowing the browser and proxies to cache content.</p>
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.css](https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.css)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=1209600`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/manifest.json](https://kelrisks.beta.gouv.fr/manifest.json)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr](https://kelrisks.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/](https://kelrisks.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/images/icons/safari-pinned-tab.svg](https://kelrisks.beta.gouv.fr/images/icons/safari-pinned-tab.svg)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=604800`
  
  
  
  
Instances: 5
  
### Solution
<p>Whenever possible ensure the cache-control HTTP header is set with no-cache, no-store, must-revalidate; and that the pragma HTTP header is set with no-cache.</p>
  
### Reference
* https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching

  
#### CWE Id : 525
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Strict-Transport-Security Header Not Set
##### Low (High)
  
  
  
  
#### Description
<p>HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying user agents (such as a web browser) are to interact with it using only secure HTTPS connections (i.e. HTTP layered over TLS/SSL). HSTS is an IETF standards track protocol and is specified in RFC 6797.</p>
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/sitemap.xml](https://kelrisks.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/robots.txt](https://kelrisks.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
Instances: 2
  
### Solution
<p>Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security.</p>
  
### Reference
* https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
* https://owasp.org/www-community/Security_Headers
* http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
* http://caniuse.com/stricttransportsecurity
* http://tools.ietf.org/html/rfc6797

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Base64 Disclosure
##### Informational (Medium)
  
  
  
  
#### Description
<p>Base64 encoded data was disclosed by the application/web server. Note: in the interests of performance not all base64 strings in the response were analyzed individually, the entire response should be looked at by the analyst/security team/developer(s).</p>
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `Compiler_compileModuleAndAllComponentsAsync__POST_R3__`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `additionalStoragePricePerGb/12`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.css](https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.css)
  
  
  * Method: `GET`
  
  
  * Evidence: `iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAADsSURBVEhLY2AYBfQMgf///3P8+/evAIgvA/FsIF+BavYDDWMBGroaSMMBiE8VC7AZDrIFaMFnii3AZTjUgsUUWUDA8OdAH6iQbQEhw4HyGsPEcKBXBIC4ARhex4G4BsjmweU1soIFaGg/WtoFZRIZdEvIMhxkCCjXIVsATV6gFGACs4Rsw0EGgIIH3QJYJgHSARQZDrWAB+jawzgs+Q2UO49D7jnRSRGoEFRILcdmEMWGI0cm0JJ2QpYA1RDvcmzJEWhABhD/pqrL0S0CWuABKgnRki9lLseS7g2AlqwHWQSKH4oKLrILpRGhEQCw2LiRUIa4lwAAAABJRU5ErkJggg==`
  
  
  
  
Instances: 3
  
### Solution
<p>Manually confirm that the Base64 data does not leak sensitive information, and that the data cannot be aggregated/used to exploit other vulnerabilities.</p>
  
### Other information
<p></p><p>���W���&�)^2�n��'t	e</p><p>���w���,�w?��O�w�</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Suspicious Comments
##### Informational (Low)
  
  
  
  
#### Description
<p>The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.</p>
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `query`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/polyfills.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/polyfills.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `Query`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `bugs`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/polyfills.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/polyfills.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `select`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `Select`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `User`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `db`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `XXX`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `where`
  
  
  
  
Instances: 11
  
### Solution
<p>Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.</p>
  
### Other information
<p>The following pattern was used: \bQUERY\b and was detected in the element starting with: "!function(e){function t(t){for(var r,a,s=t[0],l=t[1],c=t[2],u=0,d=[];u<s.length;u++)a=s[u],i[a]&&d.push(i[a][0]),i[a]=0;for(r in", see evidence field for the suspicious comment/snippet.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Modern Web Application
##### Informational (Medium)
  
  
  
  
#### Description
<p>The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.</p>
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/](https://kelrisks.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script type="text/javascript" src="app/polyfills.94d9ba0e6964c51e885f.js"></script>`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr](https://kelrisks.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script type="text/javascript" src="app/polyfills.94d9ba0e6964c51e885f.js"></script>`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/polyfills.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/polyfills.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script>`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script>`
  
  
  
  
Instances: 4
  
### Solution
<p>This is an informational alert and so no changes are required.</p>
  
### Other information
<p>No links have been found while there are scripts, which is an indication that this is a modern web application.</p>
  
### Reference
* 

  
#### Source ID : 3

  
  
  
  
### Storable and Cacheable Content
##### Informational (Medium)
  
  
  
  
#### Description
<p>The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users.  If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.</p>
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/manifest.json](https://kelrisks.beta.gouv.fr/manifest.json)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/robots.txt](https://kelrisks.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/images/icons/safari-pinned-tab.svg](https://kelrisks.beta.gouv.fr/images/icons/safari-pinned-tab.svg)
  
  
  * Method: `GET`
  
  
  * Evidence: `max-age=604800`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/images/icons/favicon-32x32.png](https://kelrisks.beta.gouv.fr/images/icons/favicon-32x32.png)
  
  
  * Method: `GET`
  
  
  * Evidence: `max-age=604800`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr](https://kelrisks.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/sitemap.xml](https://kelrisks.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/images/icons/favicon-16x16.png](https://kelrisks.beta.gouv.fr/images/icons/favicon-16x16.png)
  
  
  * Method: `GET`
  
  
  * Evidence: `max-age=604800`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/polyfills.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/polyfills.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `max-age=1209600`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.css](https://kelrisks.beta.gouv.fr/app/main.94d9ba0e6964c51e885f.css)
  
  
  * Method: `GET`
  
  
  * Evidence: `max-age=1209600`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/](https://kelrisks.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/images/icons/apple-touch-icon.png](https://kelrisks.beta.gouv.fr/images/icons/apple-touch-icon.png)
  
  
  * Method: `GET`
  
  
  * Evidence: `max-age=604800`
  
  
  
  
Instances: 11
  
### Solution
<p>Validate that the response does not contain sensitive, personal or user-specific information.  If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:</p><p>Cache-Control: no-cache, no-store, must-revalidate, private</p><p>Pragma: no-cache</p><p>Expires: 0</p><p>This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request. </p>
  
### Other information
<p>In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.</p>
  
### Reference
* https://tools.ietf.org/html/rfc7234
* https://tools.ietf.org/html/rfc7231
* http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234)

  
#### CWE Id : 524
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Timestamp Disclosure - Unix
##### Informational (Low)
  
  
  
  
#### Description
<p>A timestamp was disclosed by the application/web server - Unix</p>
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `116418474`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `13467982`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `33334444`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `01011979`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `12481632`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `02071979`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `19821983`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `958139571`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `12131415`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `607225278`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `02101989`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `147852963`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `528734635`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `02041973`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `21031987`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `16777216`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `100200300`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `07071987`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `766784016`
  
  
  
  
* URL: [https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js](https://kelrisks.beta.gouv.fr/app/vendor.94d9ba0e6964c51e885f.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `02021984`
  
  
  
  
Instances: 949
  
### Solution
<p>Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.</p>
  
### Other information
<p>116418474, which evaluates to: 1973-09-09 10:27:54</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3
