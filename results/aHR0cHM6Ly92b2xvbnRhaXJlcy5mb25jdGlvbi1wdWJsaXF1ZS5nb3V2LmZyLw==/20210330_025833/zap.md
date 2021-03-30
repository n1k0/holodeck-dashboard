
# ZAP Scanning Report

Generated on Tue, 30 Mar 2021 02:57:42


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 5 |
| Low | 5 |
| Informational | 5 |

## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- | 
| Content Security Policy (CSP) Header Not Set | Medium | 11 | 
| CSP: Wildcard Directive | Medium | 2 | 
| Reverse Tabnabbing | Medium | 11 | 
| Sub Resource Integrity Attribute Missing | Medium | 1 | 
| X-Frame-Options Header Not Set | Medium | 11 | 
| Absence of Anti-CSRF Tokens | Low | 12 | 
| Feature Policy Header Not Set | Low | 11 | 
| Incomplete or No Cache-control and Pragma HTTP Header Set | Low | 11 | 
| Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | Low | 11 | 
| X-Content-Type-Options Header Missing | Low | 11 | 
| Base64 Disclosure | Informational | 11 | 
| Information Disclosure - Suspicious Comments | Informational | 11 | 
| Modern Web Application | Informational | 1 | 
| Storable and Cacheable Content | Informational | 11 | 
| Timestamp Disclosure - Unix | Informational | 157 | 

## Alert Detail


  
  
  
  
### Content Security Policy (CSP) Header Not Set
##### Medium (High)
  
  
  
  
#### Description
<p>Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.</p>
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cnav](https://volontaires.fonction-publique.gouv.fr/mission-cnav)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mentions-legales](https://volontaires.fonction-publique.gouv.fr/mentions-legales)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/faq](https://volontaires.fonction-publique.gouv.fr/faq)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cpam](https://volontaires.fonction-publique.gouv.fr/mission-cpam)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/](https://volontaires.fonction-publique.gouv.fr/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique)
  
  
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

  
  
  
  
### CSP: Wildcard Directive
##### Medium (Medium)
  
  
  
  
#### Description
<p>The following directives either allow wildcard sources (or ancestors), are not defined, or are overly broadly defined: </p><p>frame-ancestors, form-action</p><p></p><p>The directive(s): frame-ancestors, form-action are among the directives that do not fallback to default-src, missing/excluding them is the same as allowing anything.</p>
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/robots.txt](https://volontaires.fonction-publique.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `Content-Security-Policy`
  
  
  * Evidence: `default-src 'none'`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/sitemap.xml](https://volontaires.fonction-publique.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Parameter: `Content-Security-Policy`
  
  
  * Evidence: `default-src 'none'`
  
  
  
  
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

  
  
  
  
### Reverse Tabnabbing
##### Medium (Medium)
  
  
  
  
#### Description
<p>At least one link on this page is vulnerable to Reverse tabnabbing as it uses a target attribute without using both of the "noopener" and "noreferrer" keywords in the "rel" attribute, which allows the target page to take control of this page.</p>
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a title="Voir le code source" href="https://github.com/betagouv/renforts" target="_blank" rel="noopener">Voir le code source</a>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/faq](https://volontaires.fonction-publique.gouv.fr/faq)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a title="Voir le code source" href="https://github.com/betagouv/renforts" target="_blank" rel="noopener">Voir le code source</a>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a title="Voir le code source" href="https://github.com/betagouv/renforts" target="_blank" rel="noopener">Voir le code source</a>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a title="Voir le code source" href="https://github.com/betagouv/renforts" target="_blank" rel="noopener">Voir le code source</a>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cpam](https://volontaires.fonction-publique.gouv.fr/mission-cpam)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a title="Voir le code source" href="https://github.com/betagouv/renforts" target="_blank" rel="noopener">Voir le code source</a>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a title="Voir le code source" href="https://github.com/betagouv/renforts" target="_blank" rel="noopener">Voir le code source</a>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mentions-legales](https://volontaires.fonction-publique.gouv.fr/mentions-legales)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a title="Voir le code source" href="https://github.com/betagouv/renforts" target="_blank" rel="noopener">Voir le code source</a>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a title="Voir le code source" href="https://github.com/betagouv/renforts" target="_blank" rel="noopener">Voir le code source</a>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cnav](https://volontaires.fonction-publique.gouv.fr/mission-cnav)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a title="Voir le code source" href="https://github.com/betagouv/renforts" target="_blank" rel="noopener">Voir le code source</a>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a title="Voir le code source" href="https://github.com/betagouv/renforts" target="_blank" rel="noopener">Voir le code source</a>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/](https://volontaires.fonction-publique.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a title="Voir le code source" href="https://github.com/betagouv/renforts" target="_blank" rel="noopener">Voir le code source</a>`
  
  
  
  
Instances: 11
  
### Solution
<p>Do not use a target attribute, or if you have to then also add the attribute: rel="noopener noreferrer".</p>
  
### Reference
* https://owasp.org/www-community/attacks/Reverse_Tabnabbing
* https://dev.to/ben/the-targetblank-vulnerability-by-example
* https://mathiasbynens.github.io/rel-noopener/
* https://medium.com/@jitbit/target-blank-the-most-underestimated-vulnerability-ever-96e328301f4c

  
#### Source ID : 3

  
  
  
  
### Sub Resource Integrity Attribute Missing
##### Medium (High)
  
  
  
  
#### Description
<p>The integrity attribute is missing on a script or link tag served by an external server. The integrity tag prevents an attacker who have gained access to this server from injecting a malicious content. </p>
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/~/@gouvfr/all/dist/js/all.js](https://volontaires.fonction-publique.gouv.fr/~/@gouvfr/all/dist/js/all.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script src="' + scripts[distGlobal_i] + '">`
  
  
  
  
Instances: 1
  
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
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mentions-legales](https://volontaires.fonction-publique.gouv.fr/mentions-legales)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/faq](https://volontaires.fonction-publique.gouv.fr/faq)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/](https://volontaires.fonction-publique.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cnav](https://volontaires.fonction-publique.gouv.fr/mission-cnav)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cpam](https://volontaires.fonction-publique.gouv.fr/mission-cpam)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique)
  
  
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

  
  
  
  
### Absence of Anti-CSRF Tokens
##### Low (Medium)
  
  
  
  
#### Description
<p>No Anti-CSRF tokens were found in a HTML submission form.</p><p>A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf.</p><p></p><p>CSRF attacks are effective in a number of situations, including:</p><p>    * The victim has an active session on the target site.</p><p>    * The victim is authenticated via HTTP auth on the target site.</p><p>    * The victim is on the same local network as the target site.</p><p></p><p>CSRF has primarily been used to perform an action against a target site using the victim's privileges, but recent techniques have been discovered to disclose information by gaining access to the response. The risk of information disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.</p>
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants?fonctionnaire-radio=on&publicSectorRadio=on&retired-radio=on](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants?fonctionnaire-radio=on&publicSectorRadio=on&retired-radio=on)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cpam](https://volontaires.fonction-publique.gouv.fr/mission-cpam)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics?fonctionnaire-radio=on&publicSectorRadio=on&retired-radio=on](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics?fonctionnaire-radio=on&publicSectorRadio=on&retired-radio=on)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cnav](https://volontaires.fonction-publique.gouv.fr/mission-cnav)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cnav?fonctionnaire-radio=on&publicSectorRadio=on&retired-radio=on](https://volontaires.fonction-publique.gouv.fr/mission-cnav?fonctionnaire-radio=on&publicSectorRadio=on&retired-radio=on)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cpam?fonctionnaire-radio=on&publicSectorRadio=on&retired-radio=on](https://volontaires.fonction-publique.gouv.fr/mission-cpam?fonctionnaire-radio=on&publicSectorRadio=on&retired-radio=on)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form>`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form>`
  
  
  
  
Instances: 12
  
### Solution
<p>Phase: Architecture and Design</p><p>Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.</p><p>For example, use anti-CSRF packages such as the OWASP CSRFGuard.</p><p></p><p>Phase: Implementation</p><p>Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script.</p><p></p><p>Phase: Architecture and Design</p><p>Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).</p><p>Note that this can be bypassed using XSS.</p><p></p><p>Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.</p><p>Note that this can be bypassed using XSS.</p><p></p><p>Use the ESAPI Session Management control.</p><p>This control includes a component for CSRF.</p><p></p><p>Do not use the GET method for any request that triggers a state change.</p><p></p><p>Phase: Implementation</p><p>Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.</p>
  
### Other information
<p>No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF] was found in the following HTML form: [Form 1: "public-sector-yes" "public-sector-no" "fonctionnaire-yes" "fonctionnaire-no" "retired-yes" "retired-no" ].</p>
  
### Reference
* http://projects.webappsec.org/Cross-Site-Request-Forgery
* http://cwe.mitre.org/data/definitions/352.html

  
#### CWE Id : 352
  
#### WASC Id : 9
  
#### Source ID : 3

  
  
  
  
### Feature Policy Header Not Set
##### Low (Medium)
  
  
  
  
#### Description
<p>Feature Policy Header is an added layer of security that helps to restrict from unauthorized access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting or specifying the features of the browsers can be used by the web resources. Feature Policy provides a set of standard HTTP headers that allow website owners to limit which features of browsers can be used by the page such as camera, microphone, location, full screen etc.</p>
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/sitemap.xml](https://volontaires.fonction-publique.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/robots.txt](https://volontaires.fonction-publique.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cpam](https://volontaires.fonction-publique.gouv.fr/mission-cpam)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cnav](https://volontaires.fonction-publique.gouv.fr/mission-cnav)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/](https://volontaires.fonction-publique.gouv.fr/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/faq](https://volontaires.fonction-publique.gouv.fr/faq)
  
  
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
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cpam](https://volontaires.fonction-publique.gouv.fr/mission-cpam)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/](https://volontaires.fonction-publique.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/faq](https://volontaires.fonction-publique.gouv.fr/faq)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cnav](https://volontaires.fonction-publique.gouv.fr/mission-cnav)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mentions-legales](https://volontaires.fonction-publique.gouv.fr/mentions-legales)
  
  
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

  
  
  
  
### Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)
##### Low (Medium)
  
  
  
  
#### Description
<p>The web/application server is leaking information via one or more "X-Powered-By" HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to.</p>
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat)
  
  
  * Method: `GET`
  
  
  * Evidence: `X-Powered-By: Express`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/faq](https://volontaires.fonction-publique.gouv.fr/faq)
  
  
  * Method: `GET`
  
  
  * Evidence: `X-Powered-By: Express`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens)
  
  
  * Method: `GET`
  
  
  * Evidence: `X-Powered-By: Express`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/sitemap.xml](https://volontaires.fonction-publique.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `X-Powered-By: Express`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants)
  
  
  * Method: `GET`
  
  
  * Evidence: `X-Powered-By: Express`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh)
  
  
  * Method: `GET`
  
  
  * Evidence: `X-Powered-By: Express`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/robots.txt](https://volontaires.fonction-publique.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  * Evidence: `X-Powered-By: Express`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics)
  
  
  * Method: `GET`
  
  
  * Evidence: `X-Powered-By: Express`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cnav](https://volontaires.fonction-publique.gouv.fr/mission-cnav)
  
  
  * Method: `GET`
  
  
  * Evidence: `X-Powered-By: Express`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/](https://volontaires.fonction-publique.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `X-Powered-By: Express`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cpam](https://volontaires.fonction-publique.gouv.fr/mission-cpam)
  
  
  * Method: `GET`
  
  
  * Evidence: `X-Powered-By: Express`
  
  
  
  
Instances: 11
  
### Solution
<p>Ensure that your web server, application server, load balancer, etc. is configured to suppress "X-Powered-By" headers.</p>
  
### Reference
* http://blogs.msdn.com/b/varunm/archive/2013/04/23/remove-unwanted-http-response-headers.aspx
* http://www.troyhunt.com/2012/02/shhh-dont-let-your-response-headers.html

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### X-Content-Type-Options Header Missing
##### Low (Medium)
  
  
  
  
#### Description
<p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.</p>
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/](https://volontaires.fonction-publique.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cnav](https://volontaires.fonction-publique.gouv.fr/mission-cnav)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mentions-legales](https://volontaires.fonction-publique.gouv.fr/mentions-legales)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cpam](https://volontaires.fonction-publique.gouv.fr/mission-cpam)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/faq](https://volontaires.fonction-publique.gouv.fr/faq)
  
  
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
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics)
  
  
  * Method: `GET`
  
  
  * Evidence: `5fe2-pqFADOSLtsLNjPjc5WIEUiwzkjw`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat)
  
  
  * Method: `GET`
  
  
  * Evidence: `61b4-n7lJxtAA9u97WexmUZ4CtA/qGtQ`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique)
  
  
  * Method: `GET`
  
  
  * Evidence: `5e4e-uE3Pge3abC/IiomrZ/oeGw4Frcc`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cnav](https://volontaires.fonction-publique.gouv.fr/mission-cnav)
  
  
  * Method: `GET`
  
  
  * Evidence: `69b7-kVw3l4Fide7XdMOXcfO/AgnT5uA`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh)
  
  
  * Method: `GET`
  
  
  * Evidence: `5e81-K7XEmk08SScKfwEv+QjfuC5zf10`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/](https://volontaires.fonction-publique.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `6745-+wjdROXOvTd82eQNitlof4RFRoQ`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants)
  
  
  * Method: `GET`
  
  
  * Evidence: `60ca-gSThzt2xoAd3nfqXtat7QLegi5M`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cpam](https://volontaires.fonction-publique.gouv.fr/mission-cpam)
  
  
  * Method: `GET`
  
  
  * Evidence: `5cb3-RXV1jN5iiGKz1HGl3nXLG3vYoVY`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens)
  
  
  * Method: `GET`
  
  
  * Evidence: `5e81-bI3ItI99YzglwCZc1xLQuBRn9Ts`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mentions-legales](https://volontaires.fonction-publique.gouv.fr/mentions-legales)
  
  
  * Method: `GET`
  
  
  * Evidence: `1fa1-4kxuB9SOf7V+bdS3Ck7V0ZyG5A4`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/faq](https://volontaires.fonction-publique.gouv.fr/faq)
  
  
  * Method: `GET`
  
  
  * Evidence: `59ff-kPqYrDiBNXPjIDk7QpAEWMI7Xhk`
  
  
  
  
Instances: 11
  
### Solution
<p>Manually confirm that the Base64 data does not leak sensitive information, and that the data cannot be aggregated/used to exploit other vulnerabilities.</p>
  
### Other information
<p>������\x00003�.�\x000b63�s��\x0011H��H�</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Suspicious Comments
##### Informational (Medium)
  
  
  
  
#### Description
<p>The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.</p>
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh)
  
  
  * Method: `GET`
  
  
  * Evidence: `todo`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/faq](https://volontaires.fonction-publique.gouv.fr/faq)
  
  
  * Method: `GET`
  
  
  * Evidence: `todo`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics)
  
  
  * Method: `GET`
  
  
  * Evidence: `todo`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cnav](https://volontaires.fonction-publique.gouv.fr/mission-cnav)
  
  
  * Method: `GET`
  
  
  * Evidence: `todo`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens)
  
  
  * Method: `GET`
  
  
  * Evidence: `todo`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/](https://volontaires.fonction-publique.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `todo`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cpam](https://volontaires.fonction-publique.gouv.fr/mission-cpam)
  
  
  * Method: `GET`
  
  
  * Evidence: `todo`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-logistique)
  
  
  * Method: `GET`
  
  
  * Evidence: `todo`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat)
  
  
  * Method: `GET`
  
  
  * Evidence: `todo`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants)
  
  
  * Method: `GET`
  
  
  * Evidence: `todo`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mentions-legales](https://volontaires.fonction-publique.gouv.fr/mentions-legales)
  
  
  * Method: `GET`
  
  
  * Evidence: `todo`
  
  
  
  
Instances: 11
  
### Solution
<p>Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.</p>
  
### Other information
<p>The following pattern was used: \bTODO\b and was detected 2 times, the first in the element starting with: "<!-- todo(estellecomment) : import min css and js -->", see evidence field for the suspicious comment/snippet.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Modern Web Application
##### Informational (Medium)
  
  
  
  
#### Description
<p>The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.</p>
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/~/@gouvfr/all/dist/js/all.js](https://volontaires.fonction-publique.gouv.fr/~/@gouvfr/all/dist/js/all.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script src="' + scripts[distGlobal_i] + '">`
  
  
  
  
Instances: 1
  
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
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/robots.txt](https://volontaires.fonction-publique.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cpam](https://volontaires.fonction-publique.gouv.fr/mission-cpam)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-cadre-specialise-en-marches-publics)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/sitemap.xml](https://volontaires.fonction-publique.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/mission-cnav](https://volontaires.fonction-publique.gouv.fr/mission-cnav)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/](https://volontaires.fonction-publique.gouv.fr/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-secretariat)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-communicants)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/faq](https://volontaires.fonction-publique.gouv.fr/faq)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens](https://volontaires.fonction-publique.gouv.fr/missions/cellule-de-crise-logisticiens)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh](https://volontaires.fonction-publique.gouv.fr/missions/cellule-gestionnaire-rh)
  
  
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
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000088564`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000072690`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000096791`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000059659`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000071106`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000079390`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000075991`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000063741`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000052190`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000075329`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000047667`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000125540`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000047958`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000075078`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000040886`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000057024`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000067430`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000068970`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000104799`
  
  
  
  
* URL: [https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf](https://volontaires.fonction-publique.gouv.fr/documents/plaquette_pour_superieur.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `0000062180`
  
  
  
  
Instances: 157
  
### Solution
<p>Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.</p>
  
### Other information
<p>0000088564, which evaluates to: 1970-01-02 00:36:04</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3
