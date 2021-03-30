
# ZAP Scanning Report

Generated on Tue, 30 Mar 2021 02:32:01


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 3 |
| Low | 3 |
| Informational | 5 |

## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- | 
| Content Security Policy (CSP) Header Not Set | Medium | 4 | 
| Sub Resource Integrity Attribute Missing | Medium | 1 | 
| X-Frame-Options Setting Malformed | Medium | 4 | 
| Dangerous JS Functions | Low | 6 | 
| Feature Policy Header Not Set | Low | 11 | 
| Incomplete or No Cache-control and Pragma HTTP Header Set | Low | 9 | 
| Base64 Disclosure | Informational | 11 | 
| Information Disclosure - Suspicious Comments | Informational | 12 | 
| Modern Web Application | Informational | 7 | 
| Storable and Cacheable Content | Informational | 11 | 
| Timestamp Disclosure - Unix | Informational | 11 | 

## Alert Detail


  
  
  
  
### Content Security Policy (CSP) Header Not Set
##### Medium (High)
  
  
  
  
#### Description
<p>Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.</p>
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/sitemap.xml](https://diagoriente.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr](https://diagoriente.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/](https://diagoriente.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/robots.txt](https://diagoriente.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
Instances: 4
  
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
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/4c1c676572c521914252e8b5391e12a5a8171883-4b56517e0fbf41f30f88.js](https://diagoriente.beta.gouv.fr/4c1c676572c521914252e8b5391e12a5a8171883-4b56517e0fbf41f30f88.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `<link rel="stylesheet" href="https://sibforms.com/forms/end-form/build/sib-styles.css">`
  
  
  
  
Instances: 1
  
### Solution
<p>Provide a valid integrity attribute to the tag.</p>
  
### Reference
* https://developer.mozilla.org/en/docs/Web/Security/Subresource_Integrity

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### X-Frame-Options Setting Malformed
##### Medium (Medium)
  
  
  
  
#### Description
<p>An X-Frame-Options header was present in the response but the value was not correctly set.</p>
  
  
  
* URL: [https://diagoriente.beta.gouv.fr](https://diagoriente.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  * Evidence: `ALLOW-FROM https://diagoriente.beta.gouv.fr`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/](https://diagoriente.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  * Evidence: `ALLOW-FROM https://diagoriente.beta.gouv.fr`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/robots.txt](https://diagoriente.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  * Evidence: `ALLOW-FROM https://diagoriente.beta.gouv.fr`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/sitemap.xml](https://diagoriente.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  * Evidence: `ALLOW-FROM https://diagoriente.beta.gouv.fr`
  
  
  
  
Instances: 4
  
### Solution
<p>Ensure a valid setting is used on all web pages returned by your site (if you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY.  Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.</p>
  
### Reference
* https://tools.ietf.org/html/rfc7034#section-2.1

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Dangerous JS Functions
##### Low (Low)
  
  
  
  
#### Description
<p>A dangerous JS function seems to be in use that would leave the site vulnerable.</p>
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/323797f025cf413a17fde46afddc588921e8fb37-dd45f9547f571c5f6219.js](https://diagoriente.beta.gouv.fr/323797f025cf413a17fde46afddc588921e8fb37-dd45f9547f571c5f6219.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `eVal`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/0b7b90cd-1678aede3a96c066fcac.js](https://diagoriente.beta.gouv.fr/0b7b90cd-1678aede3a96c066fcac.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `eVal`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/component---src-pages-documentation-documentation-tsx-23fd5fd7868307e1d0e4.js](https://diagoriente.beta.gouv.fr/component---src-pages-documentation-documentation-tsx-23fd5fd7868307e1d0e4.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `eval`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/2d4594b7-8e97825caa24f86f4506.js](https://diagoriente.beta.gouv.fr/2d4594b7-8e97825caa24f86f4506.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `EVaL`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/framework-4a41103737824617dd59.js](https://diagoriente.beta.gouv.fr/framework-4a41103737824617dd59.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `eVal`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/app-e1395d2c7e381ca27aea.js](https://diagoriente.beta.gouv.fr/app-e1395d2c7e381ca27aea.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `eVal`
  
  
  
  
Instances: 6
  
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
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/app-e1395d2c7e381ca27aea.js](https://diagoriente.beta.gouv.fr/app-e1395d2c7e381ca27aea.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/robots.txt](https://diagoriente.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/webpack-runtime-a72a8c654daea55e2043.js](https://diagoriente.beta.gouv.fr/webpack-runtime-a72a8c654daea55e2043.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/d1f6464711a2be548b758ab6bbf5df9dc5be083e-5c378a54c78c98700f45.js](https://diagoriente.beta.gouv.fr/d1f6464711a2be548b758ab6bbf5df9dc5be083e-5c378a54c78c98700f45.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/](https://diagoriente.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/framework-4a41103737824617dd59.js](https://diagoriente.beta.gouv.fr/framework-4a41103737824617dd59.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/0b7b90cd-1678aede3a96c066fcac.js](https://diagoriente.beta.gouv.fr/0b7b90cd-1678aede3a96c066fcac.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/a79515f9-c7b83fbbdc210e296681.js](https://diagoriente.beta.gouv.fr/a79515f9-c7b83fbbdc210e296681.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/sitemap.xml](https://diagoriente.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/styles-89fd2ae28bdf06750a71.js](https://diagoriente.beta.gouv.fr/styles-89fd2ae28bdf06750a71.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr](https://diagoriente.beta.gouv.fr)
  
  
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
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/robots.txt](https://diagoriente.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/page-data/sq/d/63159454.json](https://diagoriente.beta.gouv.fr/page-data/sq/d/63159454.json)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/sitemap.xml](https://diagoriente.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/page-data/sq/d/1947816842.json](https://diagoriente.beta.gouv.fr/page-data/sq/d/1947816842.json)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/page-data/app-data.json](https://diagoriente.beta.gouv.fr/page-data/app-data.json)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr](https://diagoriente.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/page-data/index/page-data.json](https://diagoriente.beta.gouv.fr/page-data/index/page-data.json)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/](https://diagoriente.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/page-data/sq/d/3715776872.json](https://diagoriente.beta.gouv.fr/page-data/sq/d/3715776872.json)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
Instances: 9
  
### Solution
<p>Whenever possible ensure the cache-control HTTP header is set with no-cache, no-store, must-revalidate; and that the pragma HTTP header is set with no-cache.</p>
  
### Reference
* https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching

  
#### CWE Id : 525
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Base64 Disclosure
##### Informational (Medium)
  
  
  
  
#### Description
<p>Base64 encoded data was disclosed by the application/web server. Note: in the interests of performance not all base64 strings in the response were analyzed individually, the entire response should be looked at by the analyst/security team/developer(s).</p>
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/0b7b90cd-1678aede3a96c066fcac.js](https://diagoriente.beta.gouv.fr/0b7b90cd-1678aede3a96c066fcac.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/](https://diagoriente.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `/static/odile-Regular-93680edbdd52f22d0fe76981257aeb59`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/app-e1395d2c7e381ca27aea.js](https://diagoriente.beta.gouv.fr/app-e1395d2c7e381ca27aea.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `/campus2023/components/demarcheCampus/demarche/`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/323797f025cf413a17fde46afddc588921e8fb37-dd45f9547f571c5f6219.js](https://diagoriente.beta.gouv.fr/323797f025cf413a17fde46afddc588921e8fb37-dd45f9547f571c5f6219.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `boxNumber-module--boxNumber_wrapper--2Uc-6`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/component---src-pages-faq-faq-tsx-ead7ce41f5d5e643e3e5.js](https://diagoriente.beta.gouv.fr/component---src-pages-faq-faq-tsx-ead7ce41f5d5e643e3e5.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `fr/particuliers/vosdroits/F2918`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/4c1c676572c521914252e8b5391e12a5a8171883-4b56517e0fbf41f30f88.js](https://diagoriente.beta.gouv.fr/4c1c676572c521914252e8b5391e12a5a8171883-4b56517e0fbf41f30f88.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `com/channel/UCfh-72vbjMaa-ZFzKIAF1Dw`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/robots.txt](https://diagoriente.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  * Evidence: `/static/odile-Regular-93680edbdd52f22d0fe76981257aeb59`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/sitemap.xml](https://diagoriente.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `/static/odile-Regular-93680edbdd52f22d0fe76981257aeb59`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr](https://diagoriente.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Evidence: `/static/odile-Regular-93680edbdd52f22d0fe76981257aeb59`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/component---src-pages-home-page-home-page-tsx-0165ee91e190b14872c3.js](https://diagoriente.beta.gouv.fr/component---src-pages-home-page-home-page-tsx-0165ee91e190b14872c3.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `homepage-module--home_container_home--1FTzV`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/component---src-pages-documentation-documentation-tsx-23fd5fd7868307e1d0e4.js](https://diagoriente.beta.gouv.fr/component---src-pages-documentation-documentation-tsx-23fd5fd7868307e1d0e4.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `documentation-module--documentation_container--2_SVh`
  
  
  
  
Instances: 11
  
### Solution
<p>Manually confirm that the Base64 data does not leak sensitive information, and that the data cannot be aggregated/used to exploit other vulnerabilities.</p>
  
### Other information
<p>GIF89a\x0001\x0000\x0001\x0000\x0000�\x0000,\x0000\x0000\x0000\x0000\x0001\x0000\x0001\x0000\x0000\x0002\x0000;</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Suspicious Comments
##### Informational (Low)
  
  
  
  
#### Description
<p>The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.</p>
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/app-e1395d2c7e381ca27aea.js](https://diagoriente.beta.gouv.fr/app-e1395d2c7e381ca27aea.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `bug`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/component---src-pages-cgu-cgu-tsx-ef15db7f3d0d6d08a6cc.js](https://diagoriente.beta.gouv.fr/component---src-pages-cgu-cgu-tsx-ef15db7f3d0d6d08a6cc.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `Username`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/polyfill-63fb09cf6143834a512d.js](https://diagoriente.beta.gouv.fr/polyfill-63fb09cf6143834a512d.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `username`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/0b7b90cd-1678aede3a96c066fcac.js](https://diagoriente.beta.gouv.fr/0b7b90cd-1678aede3a96c066fcac.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `SELECT`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/framework-4a41103737824617dd59.js](https://diagoriente.beta.gouv.fr/framework-4a41103737824617dd59.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `select`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/component---src-pages-home-page-home-page-tsx-0165ee91e190b14872c3.js](https://diagoriente.beta.gouv.fr/component---src-pages-home-page-home-page-tsx-0165ee91e190b14872c3.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/323797f025cf413a17fde46afddc588921e8fb37-dd45f9547f571c5f6219.js](https://diagoriente.beta.gouv.fr/323797f025cf413a17fde46afddc588921e8fb37-dd45f9547f571c5f6219.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/2d4594b7-8e97825caa24f86f4506.js](https://diagoriente.beta.gouv.fr/2d4594b7-8e97825caa24f86f4506.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `dB`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/component---src-pages-index-tsx-333b042618e8ef574243.js](https://diagoriente.beta.gouv.fr/component---src-pages-index-tsx-333b042618e8ef574243.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `query`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/4c1c676572c521914252e8b5391e12a5a8171883-4b56517e0fbf41f30f88.js](https://diagoriente.beta.gouv.fr/4c1c676572c521914252e8b5391e12a5a8171883-4b56517e0fbf41f30f88.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `select`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/a79515f9-c7b83fbbdc210e296681.js](https://diagoriente.beta.gouv.fr/a79515f9-c7b83fbbdc210e296681.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `SELECT`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/component---src-pages-education-education-tsx-1e500bc71ffa51448893.js](https://diagoriente.beta.gouv.fr/component---src-pages-education-education-tsx-1e500bc71ffa51448893.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `admin`
  
  
  
  
Instances: 12
  
### Solution
<p>Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.</p>
  
### Other information
<p>The following pattern was used: \bBUG\b and was detected in the element starting with: "(window.webpackJsonp=window.webpackJsonp||[]).push([[17],{"+ZDr":function(e,t,n){"use strict";var r=n("TqRt");t.__esModule=!0,t.", see evidence field for the suspicious comment/snippet.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Modern Web Application
##### Informational (Medium)
  
  
  
  
#### Description
<p>The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.</p>
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/polyfill-63fb09cf6143834a512d.js](https://diagoriente.beta.gouv.fr/polyfill-63fb09cf6143834a512d.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script>`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/sitemap.xml](https://diagoriente.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start': new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0], j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src= 'https://www.googletagmanager.com/gtm.js?id='+i+dl+'';f.parentNode.insertBefore(j,f); })(window,document,'script','dataLayer', 'GTM-T5SXVD3');</script>`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/4c1c676572c521914252e8b5391e12a5a8171883-4b56517e0fbf41f30f88.js](https://diagoriente.beta.gouv.fr/4c1c676572c521914252e8b5391e12a5a8171883-4b56517e0fbf41f30f88.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script>`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/framework-4a41103737824617dd59.js](https://diagoriente.beta.gouv.fr/framework-4a41103737824617dd59.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script>`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/robots.txt](https://diagoriente.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start': new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0], j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src= 'https://www.googletagmanager.com/gtm.js?id='+i+dl+'';f.parentNode.insertBefore(j,f); })(window,document,'script','dataLayer', 'GTM-T5SXVD3');</script>`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/](https://diagoriente.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start': new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0], j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src= 'https://www.googletagmanager.com/gtm.js?id='+i+dl+'';f.parentNode.insertBefore(j,f); })(window,document,'script','dataLayer', 'GTM-T5SXVD3');</script>`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr](https://diagoriente.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start': new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0], j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src= 'https://www.googletagmanager.com/gtm.js?id='+i+dl+'';f.parentNode.insertBefore(j,f); })(window,document,'script','dataLayer', 'GTM-T5SXVD3');</script>`
  
  
  
  
Instances: 7
  
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
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/icons/icon-48x48.png?v=72d8827a7ff40f1b8f3eae272a482423](https://diagoriente.beta.gouv.fr/icons/icon-48x48.png?v=72d8827a7ff40f1b8f3eae272a482423)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/favicon-32x32.png?v=72d8827a7ff40f1b8f3eae272a482423](https://diagoriente.beta.gouv.fr/favicon-32x32.png?v=72d8827a7ff40f1b8f3eae272a482423)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/sitemap.xml](https://diagoriente.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/icons/icon-192x192.png?v=72d8827a7ff40f1b8f3eae272a482423](https://diagoriente.beta.gouv.fr/icons/icon-192x192.png?v=72d8827a7ff40f1b8f3eae272a482423)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/icons/icon-72x72.png?v=72d8827a7ff40f1b8f3eae272a482423](https://diagoriente.beta.gouv.fr/icons/icon-72x72.png?v=72d8827a7ff40f1b8f3eae272a482423)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/icons/icon-96x96.png?v=72d8827a7ff40f1b8f3eae272a482423](https://diagoriente.beta.gouv.fr/icons/icon-96x96.png?v=72d8827a7ff40f1b8f3eae272a482423)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/icons/icon-144x144.png?v=72d8827a7ff40f1b8f3eae272a482423](https://diagoriente.beta.gouv.fr/icons/icon-144x144.png?v=72d8827a7ff40f1b8f3eae272a482423)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/robots.txt](https://diagoriente.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/manifest.webmanifest](https://diagoriente.beta.gouv.fr/manifest.webmanifest)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/](https://diagoriente.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr](https://diagoriente.beta.gouv.fr)
  
  
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
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/framework-4a41103737824617dd59.js](https://diagoriente.beta.gouv.fr/framework-4a41103737824617dd59.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `1073741823`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/sitemap.xml](https://diagoriente.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `63159454`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr](https://diagoriente.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Evidence: `1947816842`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/](https://diagoriente.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `1947816842`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/robots.txt](https://diagoriente.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  * Evidence: `1947816842`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/framework-4a41103737824617dd59.js](https://diagoriente.beta.gouv.fr/framework-4a41103737824617dd59.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `1073741821`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/framework-4a41103737824617dd59.js](https://diagoriente.beta.gouv.fr/framework-4a41103737824617dd59.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `1073741822`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr](https://diagoriente.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Evidence: `63159454`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/robots.txt](https://diagoriente.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  * Evidence: `63159454`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/sitemap.xml](https://diagoriente.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `1947816842`
  
  
  
  
* URL: [https://diagoriente.beta.gouv.fr/](https://diagoriente.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `63159454`
  
  
  
  
Instances: 11
  
### Solution
<p>Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.</p>
  
### Other information
<p>1073741823, which evaluates to: 2004-01-10 13:37:03</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3
