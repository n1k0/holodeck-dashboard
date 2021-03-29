
# ZAP Scanning Report

Generated on Mon, 29 Mar 2021 21:02:52


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 3 |
| Low | 4 |
| Informational | 5 |

## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- | 
| Content Security Policy (CSP) Header Not Set | Medium | 11 | 
| Sub Resource Integrity Attribute Missing | Medium | 11 | 
| X-Frame-Options Header Not Set | Medium | 11 | 
| Feature Policy Header Not Set | Low | 11 | 
| Incomplete or No Cache-control and Pragma HTTP Header Set | Low | 11 | 
| Strict-Transport-Security Header Not Set | Low | 11 | 
| X-Content-Type-Options Header Missing | Low | 11 | 
| Base64 Disclosure | Informational | 2 | 
| Content-Type Header Missing | Informational | 9 | 
| Modern Web Application | Informational | 11 | 
| Storable and Cacheable Content | Informational | 11 | 
| Timestamp Disclosure - Unix | Informational | 2 | 

## Alert Detail


  
  
  
  
### Content Security Policy (CSP) Header Not Set
##### Medium (High)
  
  
  
  
#### Description
<p>Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.</p>
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/](https://covoiturage.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/robots.txt](https://covoiturage.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/](https://covoiturage.beta.gouv.fr/operateurs/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/atchoum/](https://covoiturage.beta.gouv.fr/operateurs/atchoum/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/covoituragegrandlyon/](https://covoiturage.beta.gouv.fr/operateurs/covoituragegrandlyon/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/](https://covoiturage.beta.gouv.fr/territoires/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/niort/](https://covoiturage.beta.gouv.fr/territoires/niort/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/](https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/ilevia/](https://covoiturage.beta.gouv.fr/operateurs/ilevia/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/occitanie/](https://covoiturage.beta.gouv.fr/territoires/occitanie/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr](https://covoiturage.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  
  
Instances: 11
  
### Solution
<p>Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header, to achieve optimal browser support: "Content-Security-Policy" for Chrome 25+, Firefox 23+ and Safari 7+, "X-Content-Security-Policy" for Firefox 4.0+ and Internet Explorer 10+, and "X-WebKit-CSP" for Chrome 14+ and Safari 6+.</p>
  
### Reference
* https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
* https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
* http://www.w3.org/TR/CSP/
* http://w3c.github.io/webappsec/specs/content-security-policy/csp-specification.dev.html
* http://www.html5rocks.com/en/tutorials/security/content-security-policy/
* http://caniuse.com/#feat=contentsecuritypolicy
* http://content-security-policy.com/

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Sub Resource Integrity Attribute Missing
##### Medium (High)
  
  
  
  
#### Description
<p>The integrity attribute is missing on a script or link tag served by an external server. The integrity tag prevents an attacker who have gained access to this server from injecting a malicious content. </p>
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/occitanie/](https://covoiturage.beta.gouv.fr/territoires/occitanie/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<link rel="canonical" href="https://attestation.covoiturage.beta.gouv.fr/" />`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/niort/](https://covoiturage.beta.gouv.fr/territoires/niort/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<link rel="canonical" href="https://attestation.covoiturage.beta.gouv.fr/" />`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/](https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<link rel="canonical" href="https://attestation.covoiturage.beta.gouv.fr/" />`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr](https://covoiturage.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Evidence: `<link rel="canonical" href="https://attestation.covoiturage.beta.gouv.fr/" />`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/atchoum/](https://covoiturage.beta.gouv.fr/operateurs/atchoum/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<link rel="canonical" href="https://attestation.covoiturage.beta.gouv.fr/" />`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/covoituragegrandlyon/](https://covoiturage.beta.gouv.fr/operateurs/covoituragegrandlyon/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<link rel="canonical" href="https://attestation.covoiturage.beta.gouv.fr/" />`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/](https://covoiturage.beta.gouv.fr/operateurs/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<link rel="canonical" href="https://attestation.covoiturage.beta.gouv.fr/" />`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/](https://covoiturage.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<link rel="canonical" href="https://attestation.covoiturage.beta.gouv.fr/" />`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/](https://covoiturage.beta.gouv.fr/territoires/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<link rel="canonical" href="https://attestation.covoiturage.beta.gouv.fr/" />`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/picholines/](https://covoiturage.beta.gouv.fr/operateurs/picholines/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<link rel="canonical" href="https://attestation.covoiturage.beta.gouv.fr/" />`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/ilevia/](https://covoiturage.beta.gouv.fr/operateurs/ilevia/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<link rel="canonical" href="https://attestation.covoiturage.beta.gouv.fr/" />`
  
  
  
  
Instances: 11
  
### Solution
<p>Provide a valid integrity attribute to the tag.</p>
  
### Reference
* https://developer.mozilla.org/en/docs/Web/Security/Subresource_Integrity

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### X-Frame-Options Header Not Set
##### Medium (Medium)
  
  
  
  
#### Description
<p>X-Frame-Options header is not included in the HTTP response to protect against 'ClickJacking' attacks.</p>
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/](https://covoiturage.beta.gouv.fr/territoires/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/picholines/](https://covoiturage.beta.gouv.fr/operateurs/picholines/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/niort/](https://covoiturage.beta.gouv.fr/territoires/niort/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/](https://covoiturage.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/covoituragegrandlyon/](https://covoiturage.beta.gouv.fr/operateurs/covoituragegrandlyon/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/](https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr](https://covoiturage.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/atchoum/](https://covoiturage.beta.gouv.fr/operateurs/atchoum/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/ilevia/](https://covoiturage.beta.gouv.fr/operateurs/ilevia/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/](https://covoiturage.beta.gouv.fr/operateurs/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/occitanie/](https://covoiturage.beta.gouv.fr/territoires/occitanie/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
Instances: 11
  
### Solution
<p>Most modern Web browsers support the X-Frame-Options HTTP header. Ensure it's set on all web pages returned by your site (if you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive. </p>
  
### Reference
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Feature Policy Header Not Set
##### Low (Medium)
  
  
  
  
#### Description
<p>Feature Policy Header is an added layer of security that helps to restrict from unauthorized access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting or specifying the features of the browsers can be used by the web resources. Feature Policy provides a set of standard HTTP headers that allow website owners to limit which features of browsers can be used by the page such as camera, microphone, location, full screen etc.</p>
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/](https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/niort/](https://covoiturage.beta.gouv.fr/territoires/niort/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/occitanie/](https://covoiturage.beta.gouv.fr/territoires/occitanie/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/](https://covoiturage.beta.gouv.fr/territoires/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/ilevia/](https://covoiturage.beta.gouv.fr/operateurs/ilevia/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/](https://covoiturage.beta.gouv.fr/operateurs/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/atchoum/](https://covoiturage.beta.gouv.fr/operateurs/atchoum/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/covoituragegrandlyon/](https://covoiturage.beta.gouv.fr/operateurs/covoituragegrandlyon/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/robots.txt](https://covoiturage.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr](https://covoiturage.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/](https://covoiturage.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  
  
Instances: 11
  
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
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/](https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/niort/](https://covoiturage.beta.gouv.fr/territoires/niort/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr](https://covoiturage.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/occitanie/](https://covoiturage.beta.gouv.fr/territoires/occitanie/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/atchoum/](https://covoiturage.beta.gouv.fr/operateurs/atchoum/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/](https://covoiturage.beta.gouv.fr/operateurs/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/covoituragegrandlyon/](https://covoiturage.beta.gouv.fr/operateurs/covoituragegrandlyon/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/ilevia/](https://covoiturage.beta.gouv.fr/operateurs/ilevia/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/](https://covoiturage.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/sitemap.xml](https://covoiturage.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/](https://covoiturage.beta.gouv.fr/territoires/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
Instances: 11
  
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
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/](https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/ilevia/](https://covoiturage.beta.gouv.fr/operateurs/ilevia/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/niort/](https://covoiturage.beta.gouv.fr/territoires/niort/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/](https://covoiturage.beta.gouv.fr/territoires/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/](https://covoiturage.beta.gouv.fr/operateurs/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/robots.txt](https://covoiturage.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/atchoum/](https://covoiturage.beta.gouv.fr/operateurs/atchoum/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/sitemap.xml](https://covoiturage.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/](https://covoiturage.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/occitanie/](https://covoiturage.beta.gouv.fr/territoires/occitanie/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr](https://covoiturage.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  
  
Instances: 11
  
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

  
  
  
  
### X-Content-Type-Options Header Missing
##### Low (Medium)
  
  
  
  
#### Description
<p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.</p>
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/atchoum/](https://covoiturage.beta.gouv.fr/operateurs/atchoum/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/ilevia/](https://covoiturage.beta.gouv.fr/operateurs/ilevia/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/](https://covoiturage.beta.gouv.fr/operateurs/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/occitanie/](https://covoiturage.beta.gouv.fr/territoires/occitanie/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/](https://covoiturage.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr](https://covoiturage.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/](https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/niort/](https://covoiturage.beta.gouv.fr/territoires/niort/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/sitemap.xml](https://covoiturage.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/covoituragegrandlyon/](https://covoiturage.beta.gouv.fr/operateurs/covoituragegrandlyon/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/](https://covoiturage.beta.gouv.fr/territoires/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
Instances: 11
  
### Solution
<p>Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.</p><p>If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.</p>
  
### Other information
<p>This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.</p><p>At "High" threshold this scan rule will not alert on client or server error responses.</p>
  
### Reference
* http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx
* https://owasp.org/www-community/Security_Headers

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Base64 Disclosure
##### Informational (Medium)
  
  
  
  
#### Description
<p>Base64 encoded data was disclosed by the application/web server. Note: in the interests of performance not all base64 strings in the response were analyzed individually, the entire response should be looked at by the analyst/security team/developer(s).</p>
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/scss/styles.css](https://covoiturage.beta.gouv.fr/scss/styles.css)
  
  
  * Method: `GET`
  
  
  * Evidence: `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`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/favicons/safari-pinned-tab.svg](https://covoiturage.beta.gouv.fr/favicons/safari-pinned-tab.svg)
  
  
  * Method: `GET`
  
  
  * Evidence: `org/TR/2001/REC-SVG-20010904/DTD/svg10`
  
  
  
  
Instances: 2
  
### Solution
<p>Manually confirm that the Base64 data does not leak sensitive information, and that the data cannot be aggregated/used to exploit other vulnerabilities.</p>
  
### Other information
<p>wOFF\x0000\x0001\x0000\x0000\x0000\x0000\x0010�\x0000\x000b\x0000\x0000\x0000\x0000%�\x0000\x0001\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000\x0000GSUB\x0000\x0000\x0001\x0008\x0000\x0000\x0000;\x0000\x0000\x0000T �%zOS/2\x0000\x0000\x0001D\x0000\x0000\x0000=\x0000\x0000\x0000V;HG�cmap\x0000\x0000\x0001�\x0000\x0000\x0001d\x0000\x0000\x0005\x001a\x001c���glyf\x0000\x0000\x0002�\x0000\x0000	�\x0000\x0000\x0016�'��?head\x0000\x0000\x000c�\x0000\x0000\x0000-\x0000\x0000\x00006\x0016&\x001e�hhea\x0000\x0000\x000c�\x0000\x0000\x0000\x0016\x0000\x0000\x0000$\x0000�\x0000�hmtx\x0000\x0000\x000c�\x0000\x0000\x0000\x000f\x0000\x0000\x0001\x0014\x001a�\x0000\x0000loca\x0000\x0000\x000c�\x0000\x0000\x0000�\x0000\x0000\x0000�����maxp\x0000\x0000
t\x0000\x0000\x0000\x001f\x0000\x0000\x0000 \x0001T\x0000Jname\x0000\x0000
�\x0000\x0000\x0001\x001d\x0000\x0000\x0001�\x0014���post\x0000\x0000\x000e�\x0000\x0000\x0001�\x0000\x0000\x0004��\x0004��x�c`d``�b0`�c`rq�	a��I,�c�b`a�\x0000�<2�1'3=��\x0003�\x0003ʱ�i\x000e f��\x0002\x0000&;\x0005H\x0000x�c`dHf���������\x0006$���\x0001\x0003\x000b�$\x0003\x0003\x0013\x0003+3\x0003V\x0010������\x000bC</p><p>��	&\x0019\x0018\x0018A\x0004\x0000�\x0018\x0006�\x0000\x0000\x0000x���gN�@\x0000\x0005�\x001a�\x000ci�9�s�\x0001|�=���\x0016>\x0001���\x0018k��[NR��~�];�\x0015������z��̷\x0019n�\x000b�4�\x0014�W��O=�\x001c��\x0019��k���\x001d\x0006\x0018d��o�.��1�\x0004�L1�\x000c��1�\x0002�,��</p><p>����\x0006�l��\x000e���\x0001�\x001cq\���3ι��+���;�y��'�y�7����'_���t�t\x001dڽg�k\x0015���\x0005�\x001d\x0008׳�\x000fwH�	�@`\x0007\x0003;\x0014��p�T#��_W�\x0006v,�そ\x0008�d`�\x0002;\x001dؙ��\x0006v.��]\x0008�b`�\x0002�\x001cؕ��\x0006v-���\x0008�f`�\x0002�\x001d؝��\x0006v/���=\x0008�a`�\x0002{\x001cؓ�o�N\x0003{\x0016���^\x0004�2�W��\x000e�M`o\x0003{\x0017���>\x0004�1�O�}\x000e�K`_\x0003�\x0016����\x0002�\x0011���~\x0005�\x000c�_���(x��Xms�H\x0012f\x0006�\x0019^\x00052#�e˖�EYN�\x0004Y�(\x0015�V�l�J�ګ�+��������p�\x0003����]Y�\x0008�~���y���k�y�?W�i'�V�\x0003\x0012�d4%W7�\x000fH^�S2be~C�#\x0016�r��u\x000fz��M��\x001b����ɉ�9����\x000b�M�����(f\x0003+�δ7�5�UH\x0015j֫�2�ЋoȔ��\x0017���U��"�\x0001�+�ߢqjǶ鸎ͼ�7M��0pMj��m��ͩA�\x0001LĎ\ �0\x000c\x0018ÙɃ��
'\x0008x`{6|\x0005�6����󏣽�΁�|&g2��<��-�59�D\x00032\x0015a(B�#�X\x001d��tqW�PLwt6w`�����_��h\x0007�\x0019��%\x0019�oI�s9�g�\x0015\x0019��?���\x001aL\x0008q��\x001a\x0006�L?\x00081�R3\x001a6|�\x000b�m[�e\x001cf\x0001sI��F�\x000c
�0����\x0018K�D��oڝ&4��<+������S�\x0013�\x001e�c�\x0019����hW�ri\x001e\x001e�o$��Y}�\x000e,��\x0012���a�+\x000b��\x0003:��qk��5pJ�\c\x000e���I�\x000e��9�\x0011;܎�\x001dPM�-�\x0013M�\x0019��l�P\x0013��\���
ϥz�~�b�l���Ԉt��繙�\x001e��y</p><p>4�r�s��U��(�i�\x0000F��3[\x001e��g�D͓�\x000f��>�#OE\x0012��:cg�S�	\x000ebڎ\x001dz\x0012g�k_�j�k�ح\x0014�\x001aTy�B��?h?`�}\x0015=X�)\x001b��Y�;&����Hpy�g�N'k�߆D��i`%�8�:!:���(�:$�vm��b-�2��v"�����\x001aW�
]\x000b�\x0002�/`VٯL��r�����{�.)|�</p><p> \x0014"\x0008D8���w��./'c����qojM\x001dL�\x000e>��1</p><p>e��]�f��1\x0013{�v\x0000�^��� ��KX�\x0014��4ُh���|��f�\x0011�\x0018��\x0019ز.�HB���zs\x0002�\x0016�P��X�[�	\x0013$\x001cD\x0008�\x0004�\x0017iQ��Ԓ��\x0010�7q\x0003A"��:\x001e�\x0007�\x0018�l\x001d�\x0014ug0\x0006K(O�s<٘\x000c�s\x0008�e}���Y�X���*7���\x000e^U\x000c�*��\x0017	KS�\x0008)N\x0013���L޶��A#5X:e���^�!�� |K\x000c�\x0012��z�t�R�@\x0002_[[�sF�Ϸ$�2n?ޟ���01�d�L��l��A��je*/��V/�t>�SAi����:e�\x0007k1�	��k��\x0000.Y�o�=\x001f<;�.�j\x001e�\x0014�+��q]ˡ�7Jjq���\x001e���Q\x0007Ǔ�.\x000fq�	�	\x001cG\x0018�	����qB�½�</p><p></���\x0011�c�\x0008����\x0007T W;�N�wZ\x0001l|�DH�c��\x0016eƦ��36�q\x0006�t�\x0015p</p><p>�\x0006T��X��p�?ح�S7�r�<��P���\x0018�v�\x000b8���K�k�3=���:�3�S±<AL�\x0013�c��3�\x0000G.\�'3�\x001d���θ��\x0007\x000f�\x0013�</p><p>�P�J|ʕD�\x0001�9\x0017^\x0018>�\x0005���>	���
�f\x000e��3�j��+CMۘ�\x0017`�\x0013�d\x0011���0��L��%�+�Z�W\x0017�\x000cX�\x0015���J���l~K��\x0010�\x00022\x000bŏ\x0012\x0012݂�&�H�Bʖ\x001d\x001f�wKZr[�����'`�\x0003�Xm\x000c\x0014A4]6��\x0001�\x0013�
\x0003�\x0010��%���J�.�J�tt:�f���P�\x0018\x0015\x000f�#J�W��\x001em�@�a(z�\x0016��B��X�˙JU9��1��9n83���\x0000�S#x�U���J�#�I\x0002����K�>��@E���u�Ր�\x000e�H;��&	�����Jن/V\x0011�<؞�#�
ѐ�BXI3ϒf�����!P;+`��\x0015�1A]��P�X�T1�\x0017xB0˵X(@d/0�\x0017\x0014�__\x0008_@�l×\x0019\x0001&�����]�����-�\x001e��\x0002�D������!\x0014�
�m�>\x0000�N�\x000e��B�:>o��
�C�o\x001a-�y̎��.�h'�\x001c�Z�fFY�\x0010�,.w��=\x001c.�urr_ѯf�\x001d\x000c�/��v���3�:�:��A�����\x001b�\x001e)~>\x0016?�/�嬝�1��FҔ	|���Y]w�祮*��Ĝ"\x001am`�z�3�,�z���������G6l~ Gp�W��A�T���|B0�ϰ�\x0012\x000c�g�·w�>!-�\x001d}��2\x0019*��1�\x0012&U��~�'�|!ꊠ��kL@�鱴��t���\x0010#�x\x001eѵ�;q�����\x0007�\x0013*޶��`ms}S�(���;@\x000b_;ԋ!�L\$\x0000�\x0010�<��ԩډe\x0000���u+:��\x000e\x0015)�:0��6F��u�{,\x001e� ���'y�+_5\x0016�U\x0001�؈!�^��\x0008\x0007_�M\x001d\x0004��l\x0003�bԲ\x00057	��}(�{r��ϴ\x0014[%�{\x0001\x0017���0���B!�MC(V�����PF)\x000c\x0003�\x0010�s�z���G�J�\x0003����^\x0001;��,�ɀ4�@	t�e��ezFup�R��佐�\x001c0m�:�K�^�O��\x0001�ߐ\x0001e�a�y\x000c�\x0015�Tq</p><p>>�C,\x000e����s�n���/�\x000ff��Ad��Ca���/��MC����W5\x0017��΅�@CȜ��\x001b\x000e�ʆБ&[���wΞꃔXe��f;</p><p>K��D�S\x0003͠RǉL���X�E��P����?U\x000f���}�n=\x000f��]�5]fwm�\x001b��q\x0002�
�\x000e#�`3��;����o�|�U3h�\x001f�u��dz�=\x0005���\x0004ބ\x0011�Q��A\x0017̕z�0Y3cB�jC�O2\x001fw�\x0002�
�q�\x0013v�/�NG;RjT[J+���ʨ;�ʴP6�\x001d\x0000��-V�p�1�7�\x0004���f��\x001drษJeQ��\x0012���8+q͟\x0007\x0018����\x00121\x001d�93�9��!ѻ��%l\x0001�\x001c�\x001e�\x001d�n���A\x0005c\x0015\x0011xџ�ً8�����^�_���_\x0000����\x000b�ټ\x000c��}R�c\x000fz\x00152�N��}��a�\x0019�x������o̧�3Q�y\x0006��Z�[\x001f���t�(�%���\x000cG�J\x0004�%zL\x0007\x0011\x00069x\x0014;��N\x0010���:\x0010�8\x001a[\x000eռ���H6�<��>BO��,��\x0003�\x0006��x�c`d``\x0000�Wy"��6_\x0019�\x0019R�"\x000c�\x0003?�C���	@���	�\x0001\x00003L</p><p>/\x0000\x0000\x0000x�c`d``Ha`@"\x0019\x0019P�+\x0000\x001d�\x0001t\x0000\x0000x�c`\x0000��Q��\x00018�\x001a�\x0000\x0000\x0000\x0000\x0000\x00006\x0000�\x0000�\x0000�\x0001\x0014\x0001(\x00018\x0001L\x0001b\x0001|\x0001�\x0001�\x0001�\x0001�\x0001�\x0001�\x0002\x0006\x0002\x0016\x0002>\x0002t\x0002�\x0002�\x0002�\x0003\x0012\x00038\x0003d\x0003~\x0003�\x0003�\x0003�\x0004,\x0004�\x0004�\x0004�\x0004�\x0005\x0016\x0005H\x0005�\x0005�\x0005�\x0006\x0016\x0006V\x0006z\x0006�\x0006�\x0006�\x0006�\x0007(\x0007P\x0007�\x0007�\x0008\x0012\x0008L\x0008�\x0008�	\x000c	,	T	v	�	�</p><p>\x000e</p><p>></p><p>v</p><p>�</p><p>�\x000b"\x000blx�c`d``pe�c`e\x0000\x0001& �\x0002B\x0006��`>\x0003\x0000\x0016\x0012\x0001�\x0000x�]��N�0\x0014�O��h\x0010\x0002!1��\x000bR�3�\x0001ڙ\x000e���I[%q丕*13�\x0014�<\x0005�ŉ{%*l��;�\x001e_\x001b�\x0003~\x0010�[\x0001��v��\x001b�\x000b�Iw�\x0003��\x0010!��GT/�c�b"\x001c�	o�\x0010\x000cn錑	�p�Z�O�]x@�\x0010\x001er�������\x00181��CL��>5u��űL�g_bm۽��<�y�ֵ��әڞU{*\x0016��*��R+S;]�F5�\x001ctꢝs�r:�ŏRSa�\x0014�n��F�#J$�W�\x001f�LX�tZa�\x0008������g\x00128�\x00193[�Y[�8{A�!�Ι1�H+�K�܆N�{\x0007:)�\x0008;��\x0012S��_>�W�0�Sb\x0000\x0000\x0000x�mR�z�0\x0010d��r���N�\x0014�W�9�!Ò�@D\x001c.o\x001fi\x00178�ï���YiP�\x0010ȇ���.\x0016p</p><p>�q\x0006gq\x000e�X�2V0�\x0010�\x0018a
cL��󸀋��&�p	�q\x0005Wq
�q\x00037q\x000b�q\x0007wq\x000f��\x0000\x000f�\x0008��\x0004!��\x0019��\x0005��\x0012��\x001ao�\x0016��\x001e\x001f�\x0011��\x0019_����������ů`���T�,LR�[�ӜF*��(��&��J���\x001aJ��� ��A�|��e�CS"\x0013\x001b\x001d^:;[���ӽ�\�=�Xv</p><p>k������)��Q���1}n:9YY�JU��P���Z&\x0013��\x0005���r*s�qES���m\x001e�CI(Ҧ�^��x�\x0012��\x0019�_���\x0007����-Q�ʟ\x0010�	\x001d���J{&{\x0017�H�\x0007\x001e�$�F7Ga��]�I��%^��\x000f���\x0013�n����ybl�f�ɹ�\x0013�Q\x001b�\x0007;2b-S�\x0016�\x0011G�Q^�۵�G�BU��N*�Vhu$s���Ms\x0017����m�VT�ǝ3���X*�2�\x0010�Q��:\x0017F|⒔�������'�\x0005qN�FW��-9u�nGV��'���Zp���;�W��\x001f8\x000bp</p><p>\x0000</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Content-Type Header Missing
##### Informational (Medium)
  
  
  
  
#### Description
<p>The Content-Type header was either missing or empty.</p>
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/images/label.webp](https://covoiturage.beta.gouv.fr/images/label.webp)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/images/operateur.webp](https://covoiturage.beta.gouv.fr/images/operateur.webp)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/images/outils.webp](https://covoiturage.beta.gouv.fr/images/outils.webp)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/images/covoitureur.webp](https://covoiturage.beta.gouv.fr/images/covoitureur.webp)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/images/documentation.webp](https://covoiturage.beta.gouv.fr/images/documentation.webp)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/favicons/site.webmanifest](https://covoiturage.beta.gouv.fr/favicons/site.webmanifest)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/images/plateforme.webp](https://covoiturage.beta.gouv.fr/images/plateforme.webp)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/images/attestation.webp](https://covoiturage.beta.gouv.fr/images/attestation.webp)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/images/territoire.webp](https://covoiturage.beta.gouv.fr/images/territoire.webp)
  
  
  * Method: `GET`
  
  
  
  
Instances: 9
  
### Solution
<p>Ensure each page is setting the specific and appropriate content-type value for the content being delivered.</p>
  
### Reference
* http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx

  
#### CWE Id : 345
  
#### WASC Id : 12
  
#### Source ID : 3

  
  
  
  
### Modern Web Application
##### Informational (Medium)
  
  
  
  
#### Description
<p>The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.</p>
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/picholines/](https://covoiturage.beta.gouv.fr/operateurs/picholines/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a class="rf-service__title" href="#" title="Registre de preuve de covoiturage">Registre de preuve de covoiturage</a>`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/](https://covoiturage.beta.gouv.fr/territoires/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a class="rf-service__title" href="#" title="Registre de preuve de covoiturage">Registre de preuve de covoiturage</a>`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/](https://covoiturage.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a class="rf-service__title" href="#" title="Registre de preuve de covoiturage">Registre de preuve de covoiturage</a>`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/](https://covoiturage.beta.gouv.fr/operateurs/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a class="rf-service__title" href="#" title="Registre de preuve de covoiturage">Registre de preuve de covoiturage</a>`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/occitanie/](https://covoiturage.beta.gouv.fr/territoires/occitanie/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a class="rf-service__title" href="#" title="Registre de preuve de covoiturage">Registre de preuve de covoiturage</a>`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr](https://covoiturage.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a class="rf-service__title" href="#" title="Registre de preuve de covoiturage">Registre de preuve de covoiturage</a>`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/ilevia/](https://covoiturage.beta.gouv.fr/operateurs/ilevia/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a class="rf-service__title" href="#" title="Registre de preuve de covoiturage">Registre de preuve de covoiturage</a>`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/atchoum/](https://covoiturage.beta.gouv.fr/operateurs/atchoum/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a class="rf-service__title" href="#" title="Registre de preuve de covoiturage">Registre de preuve de covoiturage</a>`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/covoituragegrandlyon/](https://covoiturage.beta.gouv.fr/operateurs/covoituragegrandlyon/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a class="rf-service__title" href="#" title="Registre de preuve de covoiturage">Registre de preuve de covoiturage</a>`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/niort/](https://covoiturage.beta.gouv.fr/territoires/niort/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a class="rf-service__title" href="#" title="Registre de preuve de covoiturage">Registre de preuve de covoiturage</a>`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/](https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a class="rf-service__title" href="#" title="Registre de preuve de covoiturage">Registre de preuve de covoiturage</a>`
  
  
  
  
Instances: 11
  
### Solution
<p>This is an informational alert and so no changes are required.</p>
  
### Other information
<p>Links have been found that do not have traditional href attributes, which is an indication that this is a modern web application.</p>
  
### Reference
* 

  
#### Source ID : 3

  
  
  
  
### Storable and Cacheable Content
##### Informational (Medium)
  
  
  
  
#### Description
<p>The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users.  If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.</p>
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/occitanie/](https://covoiturage.beta.gouv.fr/territoires/occitanie/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/](https://covoiturage.beta.gouv.fr/territoires/centrevaldeloire/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/niort/](https://covoiturage.beta.gouv.fr/territoires/niort/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr](https://covoiturage.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/territoires/](https://covoiturage.beta.gouv.fr/territoires/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/](https://covoiturage.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/sitemap.xml](https://covoiturage.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/](https://covoiturage.beta.gouv.fr/operateurs/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/robots.txt](https://covoiturage.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/ilevia/](https://covoiturage.beta.gouv.fr/operateurs/ilevia/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/operateurs/atchoum/](https://covoiturage.beta.gouv.fr/operateurs/atchoum/)
  
  
  * Method: `GET`
  
  
  
  
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
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/favicons/safari-pinned-tab.svg](https://covoiturage.beta.gouv.fr/favicons/safari-pinned-tab.svg)
  
  
  * Method: `GET`
  
  
  * Evidence: `20010904`
  
  
  
  
* URL: [https://covoiturage.beta.gouv.fr/scss/styles.css](https://covoiturage.beta.gouv.fr/scss/styles.css)
  
  
  * Method: `GET`
  
  
  * Evidence: `23000091`
  
  
  
  
Instances: 2
  
### Solution
<p>Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.</p>
  
### Other information
<p>20010904, which evaluates to: 1970-08-20 14:35:04</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3
