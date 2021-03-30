
# ZAP Scanning Report

Generated on Tue, 30 Mar 2021 15:53:36


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 1 |
| Medium | 4 |
| Low | 13 |
| Informational | 9 |

## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- | 
| PII Disclosure | High | 8 | 
| Content Security Policy (CSP) Header Not Set | Medium | 11 | 
| Reverse Tabnabbing | Medium | 11 | 
| Source Code Disclosure - PHP | Medium | 2 | 
| X-Frame-Options Header Not Set | Medium | 11 | 
| Absence of Anti-CSRF Tokens | Low | 12 | 
| Application Error Disclosure | Low | 2 | 
| Big Redirect Detected (Potential Sensitive Information Leak) | Low | 12 | 
| Cookie No HttpOnly Flag | Low | 2 | 
| Cookie Without SameSite Attribute | Low | 4 | 
| Cookie Without Secure Flag | Low | 4 | 
| Cross-Domain JavaScript Source File Inclusion | Low | 11 | 
| Dangerous JS Functions | Low | 4 | 
| Feature Policy Header Not Set | Low | 11 | 
| Incomplete or No Cache-control and Pragma HTTP Header Set | Low | 11 | 
| Information Disclosure - Debug Error Messages | Low | 2 | 
| Strict-Transport-Security Header Not Set | Low | 11 | 
| X-Content-Type-Options Header Missing | Low | 11 | 
| Base64 Disclosure | Informational | 11 | 
| Information Disclosure - Sensitive Information in URL | Informational | 1 | 
| Information Disclosure - Suspicious Comments | Informational | 11 | 
| Modern Web Application | Informational | 11 | 
| Non-Storable Content | Informational | 9 | 
| Storable and Cacheable Content | Informational | 1 | 
| Timestamp Disclosure - Unix | Informational | 43 | 
| User Controllable HTML Element Attribute (Potential XSS) | Informational | 27 | 

## Alert Detail


  
  
  
  
### PII Disclosure
##### High (High)
  
  
  
  
#### Description
<p>The response contains Personally Identifiable Information, such as CC number, SSN and similar sensitive data.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/profil-utilisateur/643262795/voir](https://lemarche.inclusion.beta.gouv.fr/fr/profil-utilisateur/643262795/voir)
  
  
  * Method: `GET`
  
  
  * Evidence: `38961657400049`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/media/cache/user_profile/uploads/users/images/0400b71c8ebfb5fff47454e9771c71e2f8515092.png](https://lemarche.inclusion.beta.gouv.fr/media/cache/user_profile/uploads/users/images/0400b71c8ebfb5fff47454e9771c71e2f8515092.png)
  
  
  * Method: `GET`
  
  
  * Evidence: `677777777777777`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?location%5Baddress%5D=France&location%5BaddressType%5D=country%2Cpolitical&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D=FR&location%5Bdepartment%5D&location%5Blat%5D=46.2276380&location%5Blng%5D=2.2137490&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D=%28%2841.31433%2C%20-5.5591%29%2C%20%2851.1241999%2C%209.6624999%29%29&location%5Bzip%5D&page=3](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?location%5Baddress%5D=France&location%5BaddressType%5D=country%2Cpolitical&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D=FR&location%5Bdepartment%5D&location%5Blat%5D=46.2276380&location%5Blng%5D=2.2137490&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D=%28%2841.31433%2C%20-5.5591%29%2C%20%2851.1241999%2C%209.6624999%29%29&location%5Bzip%5D&page=3)
  
  
  * Method: `GET`
  
  
  * Evidence: `584001221343`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?location%5Baddress%5D=France&location%5BaddressType%5D=country%2Cpolitical&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D=FR&location%5Bdepartment%5D&location%5Blat%5D=46.2276380&location%5Blng%5D=2.2137490&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D=%28%2841.31433%2C%20-5.5591%29%2C%20%2851.1241999%2C%209.6624999%29%29&location%5Bzip%5D&page=4](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?location%5Baddress%5D=France&location%5BaddressType%5D=country%2Cpolitical&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D=FR&location%5Bdepartment%5D&location%5Blat%5D=46.2276380&location%5Blng%5D=2.2137490&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D=%28%2841.31433%2C%20-5.5591%29%2C%20%2851.1241999%2C%209.6624999%29%29&location%5Bzip%5D&page=4)
  
  
  * Method: `GET`
  
  
  * Evidence: `584001221343`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?location%5Baddress%5D=France&location%5BaddressType%5D=country%2Cpolitical&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D=FR&location%5Bdepartment%5D&location%5Blat%5D=46.2276380&location%5Blng%5D=2.2137490&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D=%28%2841.31433%2C%20-5.5591%29%2C%20%2851.1241999%2C%209.6624999%29%29&location%5Bzip%5D&page=1](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?location%5Baddress%5D=France&location%5BaddressType%5D=country%2Cpolitical&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D=FR&location%5Bdepartment%5D&location%5Blat%5D=46.2276380&location%5Blng%5D=2.2137490&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D=%28%2841.31433%2C%20-5.5591%29%2C%20%2851.1241999%2C%209.6624999%29%29&location%5Bzip%5D&page=1)
  
  
  * Method: `GET`
  
  
  * Evidence: `584001221343`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?location%5Baddress%5D=France&location%5BaddressType%5D=country%2Cpolitical&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D=FR&location%5Bdepartment%5D&location%5Blat%5D=46.2276380&location%5Blng%5D=2.2137490&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D=%28%2841.31433%2C%20-5.5591%29%2C%20%2851.1241999%2C%209.6624999%29%29&location%5Bzip%5D&page=2](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?location%5Baddress%5D=France&location%5BaddressType%5D=country%2Cpolitical&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D=FR&location%5Bdepartment%5D&location%5Blat%5D=46.2276380&location%5Blng%5D=2.2137490&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D=%28%2841.31433%2C%20-5.5591%29%2C%20%2851.1241999%2C%209.6624999%29%29&location%5Bzip%5D&page=2)
  
  
  * Method: `GET`
  
  
  * Evidence: `584001221343`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?location%5Baddress%5D=France&location%5BaddressType%5D=country%2Cpolitical&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D=FR&location%5Bdepartment%5D&location%5Blat%5D=46.2276380&location%5Blng%5D=2.2137490&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D=%28%2841.31433%2C%20-5.5591%29%2C%20%2851.1241999%2C%209.6624999%29%29&location%5Bzip%5D&page=5](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?location%5Baddress%5D=France&location%5BaddressType%5D=country%2Cpolitical&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D=FR&location%5Bdepartment%5D&location%5Blat%5D=46.2276380&location%5Blng%5D=2.2137490&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D=%28%2841.31433%2C%20-5.5591%29%2C%20%2851.1241999%2C%209.6624999%29%29&location%5Bzip%5D&page=5)
  
  
  * Method: `GET`
  
  
  * Evidence: `584001221343`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?location%5Baddress%5D=Oise%2C%20France&location%5BaddressType%5D=administrative_area_level_2%2Cpolitical&location%5Barea%5D=Hauts-de-France&location%5Bcity%5D&location%5Bcountry%5D=FR&location%5Bdepartment%5D=Oise&location%5Blat%5D=49.4214568&location%5Blng%5D=2.4146396&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D=%28%2849.060525%2C%201.6888659%29%2C%20%2849.7639221%2C%203.166125%29%29&location%5Bzip%5D&page=1](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?location%5Baddress%5D=Oise%2C%20France&location%5BaddressType%5D=administrative_area_level_2%2Cpolitical&location%5Barea%5D=Hauts-de-France&location%5Bcity%5D&location%5Bcountry%5D=FR&location%5Bdepartment%5D=Oise&location%5Blat%5D=49.4214568&location%5Blng%5D=2.4146396&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D=%28%2849.060525%2C%201.6888659%29%2C%20%2849.7639221%2C%203.166125%29%29&location%5Bzip%5D&page=1)
  
  
  * Method: `GET`
  
  
  * Evidence: `584001221343`
  
  
  
  
Instances: 8
  
### Solution
<p></p>
  
### Other information
<p>Credit Card Type detected: DinersClub</p><p>Bank Identification Number: 389616</p><p>Brand: DISCOVER</p><p>Category: BUSINESS CARD</p><p>Issuer: </p>
  
### Reference
* 

  
#### CWE Id : 359
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Content Security Policy (CSP) Header Not Set
##### Medium (High)
  
  
  
  
#### Description
<p>Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification](https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix](https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/currency/*/switch](https://lemarche.inclusion.beta.gouv.fr/en/currency/*/switch)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer](https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/sitemap.xml](https://lemarche.inclusion.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/login-check](https://lemarche.inclusion.beta.gouv.fr/fr/login-check)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price](https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/login-check](https://lemarche.inclusion.beta.gouv.fr/en/login-check)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce-disponibilitee/*/*/](https://lemarche.inclusion.beta.gouv.fr/fr/annonce-disponibilitee/*/*/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/listing-availabilities/*/*/](https://lemarche.inclusion.beta.gouv.fr/en/listing-availabilities/*/*/)
  
  
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

  
  
  
  
### Reverse Tabnabbing
##### Medium (Medium)
  
  
  
  
#### Description
<p>At least one link on this page is vulnerable to Reverse tabnabbing as it uses a target attribute without using both of the "noopener" and "noreferrer" keywords in the "rel" attribute, which allows the target page to take control of this page.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/login-check](https://lemarche.inclusion.beta.gouv.fr/en/login-check)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="https://github.com/betagouv/itou-cocorico/"
               class="by pull-right credit" target="_blank">
                Github
            </a>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="h_sl" class="btn btn-outline-primary" href="https://itou.typeform.com/to/nxG0HlYx" target="_blank" style="margin-top:18px;">
                                Faire une demande
                                <i class="icon-right-small"></i>
                            </a>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price](https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="https://github.com/betagouv/itou-cocorico/"
               class="by pull-right credit" target="_blank">
                Github
            </a>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix](https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="https://github.com/betagouv/itou-cocorico/"
               class="by pull-right credit" target="_blank">
                Github
            </a>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer](https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="https://github.com/betagouv/itou-cocorico/"
               class="by pull-right credit" target="_blank">
                Github
            </a>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/listing-availabilities/*/*/](https://lemarche.inclusion.beta.gouv.fr/en/listing-availabilities/*/*/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="https://github.com/betagouv/itou-cocorico/"
               class="by pull-right credit" target="_blank">
                Github
            </a>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/currency/*/switch](https://lemarche.inclusion.beta.gouv.fr/en/currency/*/switch)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="https://github.com/betagouv/itou-cocorico/"
               class="by pull-right credit" target="_blank">
                Github
            </a>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce-disponibilitee/*/*/](https://lemarche.inclusion.beta.gouv.fr/fr/annonce-disponibilitee/*/*/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="https://github.com/betagouv/itou-cocorico/"
               class="by pull-right credit" target="_blank">
                Github
            </a>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/login-check](https://lemarche.inclusion.beta.gouv.fr/fr/login-check)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="https://github.com/betagouv/itou-cocorico/"
               class="by pull-right credit" target="_blank">
                Github
            </a>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification](https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="https://github.com/betagouv/itou-cocorico/"
               class="by pull-right credit" target="_blank">
                Github
            </a>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/sitemap.xml](https://lemarche.inclusion.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="https://github.com/betagouv/itou-cocorico/"
               class="by pull-right credit" target="_blank">
                Github
            </a>`
  
  
  
  
Instances: 11
  
### Solution
<p>Do not use a target attribute, or if you have to then also add the attribute: rel="noopener noreferrer".</p>
  
### Reference
* https://owasp.org/www-community/attacks/Reverse_Tabnabbing
* https://dev.to/ben/the-targetblank-vulnerability-by-example
* https://mathiasbynens.github.io/rel-noopener/
* https://medium.com/@jitbit/target-blank-the-most-underestimated-vulnerability-ever-96e328301f4c

  
#### Source ID : 3

  
  
  
  
### Source Code Disclosure - PHP
##### Medium (Medium)
  
  
  
  
#### Description
<p>Application Source Code was disclosed by the web server - PHP</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/media/cache/listing_xxlarge/uploads/listings/images/4967abdfd154779ad7009803c358d0363420369b.png](https://lemarche.inclusion.beta.gouv.fr/media/cache/listing_xxlarge/uploads/listings/images/4967abdfd154779ad7009803c358d0363420369b.png)
  
  
  * Method: `GET`
  
  
  * Evidence: `<?=OáP\x0008
,q"\x0017 "µ&TCE¾Û¼ÍÓ<÷\x001c	èyv&|Sg\x00082ÍG\x0011Î1\x0016×ñæw#¦|ö¥wYºó!ù\x00080«¤Q8	P³Â\x0004ý.C\x000eicÄ\x0014@tµÊÙuÁ\x0013å«\x000cÉk~\x000f>F3$î³à)\x001f´
GÒ\x001b^kÚã^?AûM\x0008û¨ìîâýðA6\x0004É¡Îî8áóxcè\x000f."ô{¡	,|\x0019>y(0^
ïm\x0007LßÕQ¾øái~O§2·«+òÇXàÐW_\x0006½çv\x0006ø®ò;×\x0019æì>Î¹âÕt¨ø¤Í\x0017\x001cð\x0010qw\x000eã\x0010ó7»=­­S»vÿLd\Ò\x0017K'øØBv®áSØ¶á¾Ni?µ¡=ð×A-¾\x0015È9Àt 	Çè¤kxµ×\x0017\x0006£)¹g$¥}\x0011vða£S¦¬ûÊ.Ú\x0000Mù\x0003mÕë\Wgè<7g\x0015X©Z\x0007t\x001e?lgmÂðCòh\x001d\x001e?Ñ|\x0013\x0006Ì\x0004èì/:ê5Qº§¼à5¶0©\x0015m;¼!aßæ7@6Ð&P²S\x0019¸¾	þ\x0002§±{O8y\x001dûä¢WN^	=Ëf¤÷$i?°¼uóu&m¤óè8Zð£ú\;\x001cûÂ_\x001b°Âomì¤\x0010\x001a¥\x0006vóìÍ³\x000bê´ÿîÝe¨÷êÉÇj´Áhsùý½¾$\x000c½ÉÜFuûÐ7øç\x0000\x0003ý9´\x0008Fq\x001c§yÏ$qT<8»QÈQ"DQ¹*ðûÕgC·D\x001cfO¾a¤Ü\x0002\x0004;´ã»\x0006 aò\x0001\x0002\x0018·F\x0000&&n¤á¾²°W¡ü\x0019"vv\x0017~9ýC)ï»Ï86ÃZ\x0006g\x001dè(ê8S×\x00191ZÕEã%U1ôa\x0014¼\x001c×Nô:B\x0001g
\x0004?D\x001c¾×±¸Çq\x0011jvIÏºNasÇ]|l\x0013Þ#Tu´¶\x0015 >­3Ûë~µ©
¸8´§3é2ðéÁ§¼oläAÓ)åÀ\x0013Ã\x001b¿}9Xù]CM¯\x0006o\x001cÍò\x0012|mkoÏtîALNVã¤w8>¸)ç±ÌZê¤ÚÑ\V1pìD³4opô½F\x0017\x001eýö»ûø·¼ñ¹N|å¹zÑßÇ@Ô[Þù¾íú^Þç¦hÌu\x0007Úíá9<NüZnK²pEëê¹{K+\x001e-\x000c|Å\x0014¾:d`Èm2CDjø\x001c/\x000cwÒBÏðô2:·^|#Î\x0004p^m\Øl(²Õ\x0011|óÍ×Å>ª\x0005\x0003ÚÐÖ:Å\x0017Ý,ÚG&9ÈÏ\x0017\x001e<|t6ò\x0008Ð\x0007l\x000fMýÛß*\x001fíé\éSº¸Ìò¶£¦üí³ÿûê|»H¶KÀä7SQ\x001bÞÚæ¿þþ,±£SFn\x0013¯nàõòÞ÷uÄã7'£û££kß`Ç½wT·ú³ºG7ÕÁ\x001dõÚåí½ÃÀ×ÖtÀ\x000eõ91ÏÏYÍ-¤Ò£G\x0013÷[<ü*Kõ¾¦\x0013\x0000\x0000B½IDAT\x0013D\x0004ã\x0011E=OWú{ª)ÄÊ+xúåM\x0016zcJ\x0015\x0001yí¹£ÄæÞ2´_R J\x0014æµ'È¥nÁ×tMJ\x0008Âí.î
\x000eÚj4«tþmO¿N\x000cØuL1\x001fG¸Ï¾èd\x0014\x0006ë	åfØ=K{Ö\x0018Ý\x001f1°µµvÝ÷>³ÎÈ¯\x0018\x000f\x000fPV\x000erk0×Pû\x0019üEØyqqGÿâ¼ÃPF;£3D_ê,SïÚP;<,D6Ê6$´'«þ\x0007\x000f´;A,3\x0014\x000efâF\x0016³dSYÊåTwù	'9,4²'±UÙuj«\x0003\x000bGä \x000cz\x0007Æð¾
\x001c#Kô\x000bÖÒG~«k`Âiam²øâÓ)cÏáZëäó}Ù²FTG5Ê\x0019BnG§ºööQËvG×Ð]Óî:W8iËuôÁÛ=².~Úô\x0012JöÎtBÄá­¥dÕÓyÌèÂÂÿ}9f\x0011y\x0017ê\x001f[a#tG{pðtâ¾Jä§¬Ç\x0014õÁ]¤¸ø-_86¶n:ËÖè\x0019üïÆ^L\x0008ØÒa«\x0003þ*ý^5<·¼É¤Ø«W¿\x000eé\x001fí Ã¡m\x0007ØÚõÛÆ*r{¿ÛÙ\x001dúm þ.2<¯ÛDÅ6V\x0019¾
øéÏ`u-\x0018«Î\x0018
º62\x0005>°²Óq÷GàÑsu­fÀ;Q;á\x001b_IÜ0³§g°E\x0017oãÌôõÈ\x0001Ã¡jàÇ!q8r6\x0014o¢\x0015Yx{\x0012¤:\x0013Yaz±ëå@e*¤\x000cMCïf­\x0001ÁIÛ]LÙàï®ñJ\x001f¥ÚmëÀ\x0007{£¾1N\x000eur(Ö\x0001ÂXÖ!qÜí½Â\x000f»úS=¯
\x0019ëHf×¬qì\x0004¨C¡@Î ËU\x0005o\x0018«ã(L=lï\x00050·=dï^Ç\x0008grÒî¯1(³øwêRÔl©±&ê#ø>	\x0008ÿn?®\x0011\x001c^OÇ4\x0013\x001d\x0013­3^' =Û¾á¥ó\x001aÿu\x0008ðû/s6Ï&sÃ°Å\x0019¾ðtl~\x0013Ñ\x0014Ò~ê¯³3C÷´5\x001cA«ö\ß	\x000cÆ\x000f¦{hZGµrÖ¶céõ¹z»F«þÒ´9üÕï-ï\x0013¬®dÁçüÖ6|\x001côk;ìÕ¥¡\x001b
ãü£\x0013Û©¸_\x0005ÖÊO'÷9¯þ9\x0013fì».ö\x001fÿéÎï¿ù¶¨ïÂ«.;\x000c¬I»xâèUøhõØµBlT9c;\x001f>Ûñ\x0008ßuÚá uÎ_eö\\x000e|l7\x0017\x0004ãÌj[j¼d\x0006û\x0010%S!|ø!Î\x0004/\x0016åÁEÞgeGxý&»/áàK`ì¼òõ \x0017½ÖÎèU:ø&¼êÄ[ðÓFyöÑb²«Ë´í\x0002}êçÉ}y.º%ºÕ'áè_:ØkV\x001aM\x0007_z²\x001d\x0003¼µe\x0015\x0013¾x$öÏþK`\x000b8Ð\x0018GZ®D±wMá\x0002¡Æ\x000cBC¼\x000e"Ükä\x0015ÂÜ$yêû×¡C\x0004\x0010&M\x0012x\x0008¦¬«¼à*#¬Bíç:\x00085ª¼aÍq¾"µ\x0010j\x0003gr¤@zÊ(c¾qe^èÒI¬±k×\x0006\x000f`s.;ã^Æ+\x001f\x0018X¡Î\x001a¨º;á¡_yðË\x0017N°t'<½\x0018>ãºû¬\x001e\x0005ØáØ¯q=8¡]}\x001cumkov\x00155ÅÓîeK²éQ\x0006¯q\x0014ã)À.A\x001b§ÙÐ\x0018
zÀZZ6ÊÇCJå¾6\x001däF8»N¹á7\x001b1ÒOyLDÛø
¶z~¯£À³uZãðf¸\x00046ZÇ`ÎdC\x000c¢¸§\x000eCÐ6z×@Ý\x0003eª®và\x0005cõÊïé\x000cfrHY¿\x0007ö¥cØr`\x0006Øä¯SWþ÷V\x001fsoîÊ^=ö±íj»z\x0007NÅ\x0011j['ÐÜ^y66D9µÇ\x000fä\x001f³çýyxAµ²Ù«8=N²[?Æp¿Lú=)G20ßW§
½\x001fwAýÈº£ÈTôd(:úé
Á?\x0014Ç?üþ\x000f}2
á»~B\x0003Þ>I}[A\x0011¾\x0017 ä^(h4J>t\x0003¯ÆW\ôÚu2WÎ®ôîsFìO{\x0016ó[Ng\x001d\x0019ä~ÓÇgpòðWÞ*\x0017Ç¤\x000e6×+\x00052OÀ
\x001f\x001e¶\x0018ý\x0011Ô\x0004\x0018:ùtni\x0007ïi(Ü&+³\x000eþÒððYF\x001d¶ÏhM].À\x001d<¼û>+\x0010è'\x001ey£â kh\x001b\x00032\°(77ß\x0004©zö08?S\x0011\x000b\x001dÍ\Â|Pv/'ý\x001d~xªèS\x0018²9\x00043Þ}"	¿)\x0006Fú$äUDÄh×g¿s6\x001cIz\x001bÑcvÙ¢îÄ&ù\x000c£`U)GAõ\x0012ð
×º\x001dì\x0008:½\x0008\x0006P¾Y÷UF;Ö8Á\x001eüÆ¸\x000e\x000f|Ù\x0008MCW8òÒ`nä\x00052'oBè=%sa8(*3ÍÝa\x0013²\x0007Ö6½¸Àw¢¼q\x000eåÃU'1ðÚHi\x0015S2¥üÌì{;¦´³ÊÝQ´I\x0014cs¤++40ðydt\x0012ø\x000cBÝ*bð\x0003ÏçFZëëHvy\x0018|®\x001d*\Æèu²pNd#\x0003ü]'MïèÄ,H×\x0001j²^/¸­£^g.¸¬£\x0004Çá{p{gÃoKVÐ£]øçhZ+¿7cx¢Ñ\x000e½soø24¨·º©üvP®¹7º9:ºa±{ë¸o# èmâ¬à\x001c¾³\x00140ü¨á\x001aýÙ/øI^û£s6ù3ü\x001cYYbv7NPÛ¥%r­\x001fC¯åÏë1úàIlíÌÚ\x001bê\x001bb÷·ïnu\x0004
è©#Ë''\x0007gÎØHêIÖ{²-eÀuo"Â\x001dáLî\x001e¾Í\x0006&cÃxåò\x000fÏÇwÒ2eñÇçûàM\x000e/¾H
îË\x0017w~ø»\x0008ðOig&Äû\x00188\x0014HUîwÖwZM!z\x00149sòø\x0000n'ÍÒéè\x0014rax´÷\x000eª> )ÅÜß\x0007VN7ývÅß¿ÿ{aÓ_\x0016]Zãê\x0012\x0018n\x0012Ó\x0013¾\x000cõ\x0019P\x0003\x000e\x0008U@vñ®¼(ÊFmc\³&p¼?å'e2ÄÖ\x0008ÔÞÙæ\¾U\x0000à4³\x0000?=ï¬¼\x001f÷¨¹!³ã³ÕC\x0005ÍËF¸MJç\x000f£kØ)«]A\x000f|­Ãäþp3Î£ÈqðX\x0006®A \x001b\x001dëØÜ§Deü¹gø5õ¹v"ÿåç\x001fëÜÍÐ[_Û·­\x0006G\x0017\x0007ÖùÅ±W±C\x0017%µÈFµî¯aGs×ÌÒ¤Ø\x0019\x000cGÀ\x0011QÌ\x000b1,¸-=kô\x000b2Z\x0013¸k\x0011µehSG¹kÇ\x0001ïà6NJ®uG0íû\x000cc£Lp6ÊÝâ93Ùyeë´äô~­3\x0013\x0005i\x001fnëÄuÎ`/¾ôMÛ\x000e´Á*ïÞÊL½:cð`¬A«f¿AR>©\x000b^u*ÇòÐ÷ÅÇµéPg4\x001eÇâä~ñm@`õKpÊ§¥Tüã\x001f\x000bþs2Ý4(6ø9\x0001ß
|¢Gz^Ñ5:«^\x001cÐÊfÌ/|ÊTÒÌ\x0003¤½8
ºnýèï¿ù}\x001dâ÷?g	O¢Ùµ=pßÅ1íÄ©kl¬øÇyx\x0012I\x0018C¦r¦ÛIÏ\x0012,)\x001bONÙzx³ò/_Ã¿n\x001aF½qF³!ÊÓäEÓÞï¢÷G\x0019ujOY>g°\x00077ÈdÖy4Óê¬ÏöMÛxÅ9ß\x0016ÔÃ\x001d¿áN¢Kè$oúá;?\x0007?K°þô§?õåy×:àû
*Ü\x0018ÖE9Ò13@Hv²â8I\x00055\x0008 \x0019yÎ.RL/Na&*a¼^\x0019R%+\x0008SLÜ¡Û(æ\SF[î\x0003Î\x0003hÊÚÏÜM\x0013¥b\x0000x¯D\x0014z«(Ð\x0013NeVàt3ÐF\x0001EË\x001bÑ¼|%\x0018Q*Ë8D£\x00046Ë¼\x001a×VQÊÙ\x001cz¸e>þ\«!Ïðg\x001e$ ûÿþõÎ¿þ÷ÿVÞýòm\x000cD\x000eÇ:<4s:\x000eQìÃ{\x0019\x0005\x0007|r]®ÓF\x000eís!¹6=lò\x001cøq\x0012%h\x001b¯\x001dçÆ×`^j\x001bQ­s\g§GUnz×é0ÈÖ«2(0Å%\x0017µÊ¥½íXS¾\x001dYxµMuLåc`Ñ=NÚoüR<Ñ\x0002?<æÌèÉÂ\x0019Ç=Cyð{³ôÎý-\x0003ÎQN\x001b"Ñ\x001añá+^3 ç:J8±zX]<m)£®{ëPñtáÃwy<\x00068ú3Ä\x001fYª?ú¤£\x0011xúLT¶e²E§¸×Z¾ö,o+ \x001fÑi÷6
_\x0004@Öâû8ëÈC;ºÑ9ÓÙ*3N*zöâÙÌ|¿(¿m5g÷x4Àñ³\x0008TÇþ.«\x0019uøH3 \x001dûKçä) #ëÕç¼<Í2¤uTË×>µÀ\x000cÑçYvm	r:yï_|m"JÃÿïÏF$\x001c¤:ðû\x001dÝ.ÇÌðO¾ôQ;#\x00110\x0007Ntd×êZ}\x0000®vÈî¹7ëm»7\x000fÉ,ÿðÔ9\x0001Ø\x000cçÿÞ\x001d®Ø×Ò	\x000f¼ëTn\x00152ÂhÃY#	üøÑÓ¼ãDØÍ{GÂ(C\x000b3¶À Îr¥OïBaì|¦Æ\x0013§\x0016Açð­±¤Rsy¹\x0019%À5
ß\x0007yÃó\x000c\x001fô¸ïÎSVqàÍÓp1~4Îvcæ¾!Åö8Ä>¡\x0010¢«\9oïäõìt5ë1S\x0004ú9QÍsûÞxä\x000c0O²|¢öI3 ãZ	á÷*½ûÏ?þÜÞÒ=\x001dT!\x0012¢ä\x0014âÊÓè\x0018¨¶V@>Ê\x0013½ÜCÏ:
\x001d\x001eYÈa=2\x001cuHuÇh¿êmz"9¢
ZZ/ÎBn£ïâþ´áTf\x001dÞ*³h\x0006Íâ)ù
Þ?Â¿ Ñ\x000eª<\x000cMtÁÃ\x0013Þ/\x000e7²ÎÉ=pà:\x000eb\x000cb\x001dw\x000f9E\x000fðftxòªd,úZ§\x0006æâ®\x001d¿W\x000fÛ\x000eÚ\x0018¤~y\x001d&\x001aá1|uÊÍð,ñL\x001bÊÐÉà\x001c¢N8sôó\x000b6\x0001Ô¡cÊ÷©¿\x0010ömC¹'1~\x000eâËìÅiuÍ\x000f?dçC&ôª\x0003·:\x0018\vív
}ü¡\x0019ï/â;Y
pTÎSn?eÔd§{©¢Ç÷8æy\x0017Ò\x000cã§lW\x000fâ$ºÎ§oh>\x0013rYW.¸z÷.\x001b$G\x000fÈ[pÖ\x0000Næ©ÉÑç	^ºÙIþt"«WµÐAwh\x000bþéäÉL`AÖd±º¼¶\x0002¯ÇL³\x001d\x001fþÝ½\x0007
ëÊKSÐ;\x00110gNfN°É.ZÆÈn¤\x0001¶S\x0019ûIôhôïI1pÀp6NÐGÆwõ~}\x001ahòðîcù1ìQ \x0011ÂLÔð¬\x000fí³¨6\x001cË\x0001)Ç\x001ad7ç°[Ì¹¶\x000c@\x0014eÅDÈ:0âúèÒ§8p8=Î£÷¿\x0008\x0003#!Þ¦¯¢å´\x001dÝåP	ÀÞF)å2<eÃ¸Àow¦zI\x001c8_ÏDh0d|>ç\x001cs¢\x001ey­è"àYk;y7°(BaHÆ¦íÒ+öWüãý?¶üWÙ\x000cBNkóJ\x000c\x0007\x000e\x000eåÑ¯Ó!\x001c§vêxò!Ë\x00187§<;²ëÔð`\x0016ögIUüã½óK³\x0011JÚlZ%°\x001dkÛ;kÁ8)Æë¬ÃC\x0007\ÊçD=6õöü³ãÕqxp[GZ¾\x0007)\x000eN´ýô©i\x0016stã\x0004g\x0004Á)w\x0005Ae
·Qbòkç\x0007á1Áôîù¾F¼zâú8Z\x0011Ã¬\x000c!Ï§@×¹l\x001a\x0007EôT
>NzÇè\ÉP%8ìHcuZÛ×ç¶_G\x0014Ú\x001bCekfqïß}\x0006F¢ÇÁ±«8ð*:úî]ò¡^ô6_¾W,¥ÑTyä/8ÕAÄqþx÷çê:OÆM\x000eF¿ªë]hÿ©\x0006|³ã \x001c¡SYÞ]Ú\x0012©u¸\x001f½]SNuòêÏ÷¬záx\x001e¦óÈ$}ófaø­¾£ãbHÙ®%oî­Ì0\x001cOg\x0014iô0oðlÞ\x00159ØæÊ»zÊN£]Ô\x000e×ÜÅ¬ç%KÏ:çÚæ¤¶{Úæ8]o12"c£=~
~^ '¥PøxÃ¨\x0007\x000fé\x0005=\x0006tzäË3p¾ß}÷·\x0003ÿ¢£tÀÙ\x0019\x001cw\x0018\x001fañ
Ûû\x0012$\x0004'©
¹(E¬@r§HU\x00107\x0004n#	Jq\x0003Â)g\x001c¡ØBÌ¥W¢69\x0006\x0005\x000fî!&Á\x0004aÔ«"ØR-°ºµÌ
þ\x001cBæ LÌ\x0011¹êÙ?e0f
Coã­0c¼\x001c¼YOþæq}&ÒÆÑìZË*L`)û&ëk\x0019wõ»oêìo¢(}\x001e9Æ¬\x001c\x001aÆ¸'éN\x001dOnfØõ\x0006ç\x0018Ü°\x0013OÃ¥¾/\x001b6ù\x000b­\x000ct\x001d
^âÿ£l`bõÄ:\x0019<XúV¦Á:í\x0000ÞØ³{ôðËà<i\x0011x­\x0003ÑßàV©?i¥PcüÚzhÇ1[Ü\x0019	Dw"{2và«üèâF6psÊ(·

æêÚèäy\x0012,Îó~I\x0018£\x0017ÃÁ7M=Õ\x001d¥þ8âÅ
Ì¤ÂÎÒ+£ùJº\x001b\x0019Ñ=å×ñúÎ)é`è4úuXh@¿{tðÃ\x001fj;Ê¡KGeÌPS¤9©v®ù¬`ðí\x0000Ã»Ècz$:Ì#¡?%âg\x000bæIE.9ê_~1<ÍjÈ\x001eÂX6¨=ôÌ\x0008êa'U~È.ml­x»o_ª\x0017]#\x0012åÑC¯;Z\x000cÑl\x0003ÅwO7õÉÅÀ/.Ñ»¥G­'¥Á\x001eéÒèø¤×DÍüÇ¼úzF°F(Åµ#³\x000e\{9åCÉe&7\x0008Às)áÑÔ@ën¢©¤&û\x0004\x00083rdwo³LÞß«Ýïg¯WAÖ¼µál^_\x001d\x001eÛ¹Zýðøð0pÈ\x000cÇ®ßtÉÓ\x000f?|_ú§£Õ1\x000c­ôç¦¡z\x0008èkDÂ\x001cÞZvm,UÊ\x001boô\x0002@£ËÔ÷)*³S{£6<
aØÁºe\x0008(×ë´ÓkÔ§ÇÏH\x0015¢Êi#dfÍÁNdXcn\x000f7ÆÐÞ5Å£j\x0018É1PL\x00115¥Íû{\x001cS\x001fMmÏ¢\x0006î&7	¿&°Ã<9æÎÐBô°ìYûê÷ÌÈ\x001fc\x000cnzQÏìÏ«\x0011¼54N÷É«É7Uá¯Ãýéç*ÔÒ\x001d\x001aÝô¯jX|ûêêð¡ÃÚÚ×qZÒ\x0012{ô\x0016IèëÅ?7t3ÔÈ}#¢u:>ñ\x0007\x000cÊ1Ã&ïÞ2\x0019C"CG\x0015äàÑ\.§Wc\x001d\x001cðÊ÷q\x000c\x0013¶gp\x001exó9ï\x000fGP7Ûå\x001c¤jÂ/8t¶<BL¬#G`²{"¹Ù]¢ï\x001cü\x00021õñ\x000bÌqédÃÓ¾j$åG\x001bE]\x001cÑî>Ëe¦î¤è®N*8èl3<Ý÷WÑ\x001fNF9´
$,!2\x001cÿôIºInvf \x001fÒ³^óÍ	
:j	®øotôä\x0008LÞüÇ!MäM\x00172«\x001e¾½zùºKçEPóH¦aÿOYB$à\x0000Ë\x00069&4ñÆû¼¿=Ð\x001d\x000e¼Ë¢\x001f¿¤kÊu3åÀ\x000e1z'ú
Mïs\x001c½\x0010\x0015N§÷öuøv8?þá«YS	\x0007òå¤¦\x0003 IÉÀ\x0011\x001fæuê:¨qXø¼¨_Û®\x0019ùÐ\x000b
G:ÁlÎ­öñ·s\x0019¡¥?¥Ï!W|÷Ðd¤·Á\x0005»\x0013çKÞ£1o}Óiñ-Ñ%z.èû<=Imnßâ\x0016ødÇ~÷Ý_;z÷lñ"\x0017'ªÞJ\x0018Û\x0010\x001dCx\x0019UãLÏ×
ýáÃ,ÝAì\x0018ì\x0018ø,%2L3¢Q\x0006	ô2¨½ï\|\x000fL=³!ì\x000e;ÔäNÄ
\x001dûéG´\x001a8O9ê\x0018=\x0005§ü\x0003s°V\x001bé]Û`÷÷yñ0\x0008ü{Ù\x0000áè9\x0017p8QÊ\x0019\x0016SnJG8xá7'o\x000b.8o$îp§Êä\x0015\x001dxöX.*\x0002ÖwqèÐ¶¡¶lÝh9¼¯Bå\x0018\x001e]ÇY\x001eä¾\x000e¥QmÿÂÃð\x0004ÎòO²åôò#£\x0002Ì¡nVð÷}áÒçÓì+\x001f\x00057Ñ3\x0019_Þù\x0014\x001e¦MoQuh\x0003«\x0017\x0013=ío\x0007
¦³$'t QG-ÂÝ#³\x0006íðî?ÒQdÔ²\x001b­(\x000fßkÞÍ0ÏN_»\x0012<xí6]&\x0015}²\x0003\x0016-\x0010\x00188¦ÓN®'p¦\x001c$\x001dðÖÉI=h{füW>¢^m¬CæxÞ7¾÷\x0015\x001bèo§\x001cHöÚ4´V×\x0010>¾I©Ãïðz\x001e¡ü²°8\x001aL\x0002·9K¼\x001b>ÊEûÿêsjà±ÍwoØÚ,ûù"¹Tx{(æ]ðàL9nx9è\x001d#\x001c9Í\x001aÐ\x0019Õ9ÁCz÷þeÛá@\x0004ZHÒ¶×È\x0018î\x000b\x000eÆI\x0003jP\x0016|\x001aJD(êÇã¦½rrÜû§OcçpÀeü\x000cÝ(p"}2À?'º\x001bÍ\x001fýQvucx7\x0013G&7yçy\x001aLÑq¼­Õ¬?Ã\x0004x:q´ÌÓe9\x0002ò\x0002­~=vMôM4:zÉ
ñ]9u\x0013ÜDyÊðÙ \x001bC\x000cä§g¥\x001c\x000cpwK¼2ô\x0018I\x0003Îï¹6 â88¯¤0¼r¬#mãQä=Æ@0ZO1ùÎ÷ç~ïå»òn£hÝ\x001c?ï«,§Ý\x001aaa[S\x0010û$\x0006'{nD2]ÄSYø8üÖ^\x0015á8^×\x0007¿¡\x000f\å9ö\x0015ºßû\x0002-íTØq\x001añ¦¥¹)t*B°ÍËåØ\x001e\x0010ü\x0015\oc\x0015EÍù~º`Èê(þÔ\x0003Ò.ÃÕ³Ã«}pÄ¥\x0007.N(î\x0010´ø¥\x000c¥\x0005g~\x000f¿D^`é½á§-ã{SB\x00141õ\x0018\x0004¸û{V\x001aÌPIYCÌ\x000e»R~&U\x0012å\x0006ùlQt
\x0000\x001e#4\x000c$7ô0uÚÃ\x0016R%ctàãb@ÚÑé$\x0012KNëûß;x\x000c=¿ä<Ø¹À\x0000¯f4±z\x000eõ¶öð} ý±
Ûlâ±#2Îo#þp6d»\x0000ß¿f»ÍÄWÖ¡K\x0007j#¿ÕÕQ\x001bÑp:\x0000t!çüòûà¯ãl6°\x0019§0\x001dèt¶R\x0017ÈÈ¶t&P¼x\x001c<\x001eg¿àäö^}ã¥NAyÉÈ{G\x001f´w-\x001dC\x0003nýÛ_\x001b-<¦à#âàÙ\x0001¾H\x001d\x0008.>E±¢F\x001b°Ñ¦\x001b\x0012¼ïyøá7È#j\x001fÎiO0²Ñ²\x000eN­\x0013Õc\x001cüDøwm;Ëw\x000eýÙ¾6\x001eßÓ6­5ï[tÓà\x00159j<xMÏ\x0008Î-':Ñ(^OªB»Ô\x000e\Á\Ö§fÆª=Û\x0008¢#8BªSÈ±y­\x000e×Ï5uê@RoÁåÂ0£èVuq|÷lÇ\x0016\x0008Xù5JB¡%V8é±)û:|B±C\x0013\x0006
É¼ÈD¹£\x00103XGáYåöX"µæ9P.Ì0\x000bMÏÎüÆC\x001a'\x000c§½¦,¥©\x0002\x001c'\x000fVPþôx\x001dV\x0007¢Å¯(JÛ\x0017kÅÑ«ï\x001eCt¬sºÆÁ÷5JJ<í¥³k~-<O4M¡j\i\x001bLJ/:±>s\x001céeí¢6V¾`û½t¸>Í\x000c),ü*(Ã:ÒA±÷ØN\x0005¬uHào[à8üv¿°´\x0017££\x000fö"x\x0008ÅêH­\x001dÅèÏðrõK=p'o6Q¼ÎU»ÖZ¾ÓÁc³ÛöðÊpNÉRgOãô<7ÞHiw;y\x00087x¡U§¿ÖXrdÚëã©'I{K\x0003½Po]ÇCå8\x0002£\x001cüj\x0007Hù\x000e\x000fîfJ'×rI]¹{íÓ\x001bãêèZ¼¶gö³0Lçp
ÙµÑt#8à\x0003z81°ØÀÕ\x00171ÍÃë>¸XÜÿøÑ8­1Þ¾LJaÒhg.âè!åÈ`F\x00171³:§n\x0007\x0019\x001cÈÎúOté,8|¯}aµ-÷#\x0007ú;#k´c\x001c¥	Þ¥cÉ¤Ùè/'?ö\x000f«\x000b³Wè¤#W\x0017/x¢CÛ÷^|nqçDÅØV§\x0019}Îì\x0008\x001c\x001eÍç³åðP°×:dçÊf\x001céø\x0011rk¾]\x0007¾C­UúUu,+\x000c\x0010ä:¥ñ½K¢n
+Ú»ù ¯¾%Q\x0018vUØ9=9Âè\x0006\x001b-ê©æñ±É\x0006t·Vç\x001bð]\x0014f5¯\x0016\x0014¿\x000bÓ
\x0002'R\x000b\x0012êk\x0014\x0011Ó;+XÃ¼8Ptí±ÎÓg\x0002:£ \x0016D\x001b®\x0013ô:æÁ²k\x0004Ó5~\x0011¤ûjrU¥\x0016pXÇ²
 Ýk§Aëx:R\x0008-¢,,£¹\x0017z¥.FFã¬fÆxÖS?éqë¬ËïÐR¾\x001eßáÀ0\x001f¬	ÎPyÎÀ$:»Ks~/<uWÉWÑÀ\]Ú\x000egù¸|-O¢Ô¸und">Ñú\ÛÑÍ¦`8äYZcöõ\x000cu«\x0010\x000cpxm\x000cñ\x001dn\x001f²òÃSz'ËäOåÏ-Ï19·èå\x0004\x0001kôÀI¨FFÃ/\x001fÜµ33ãÓkx·tú®Mô¥¡¡2\x000cáZÃåv¢º\x0001ÏÜÓ	ë\x0004ÐÕò8Zmº¿×t*aÊl'çîy\x0001e
&t6o{`ÁM°G¿g®bfÊéA&®­\ñÏ¾o-4p*6<1_ ²í¤qà<ø¬ÃiÒ\x001cþG_óäàG'tx\x000cÏ:®À\x0014,¡ùÃ\x0007\x001d\x0004ú¦¬ü1Õ@÷êTçX¢ûk{ãÌÇ«·é nÈFürh¯KââÈMR	N;ºSFy[6xò3hµLÑ§²ôh=²d©'jD:\x0005.|ëpz ·a\x001d\x0000\x0013©®òld0\x001e~\x0016ìCêýû1*t<ü¬3YIÁñÎ¦\x001dÃ4Ì/c\x0006èûë{?uóè©ö}çÄHB¹:Ô8kQ"pM2hÇ¬¦Ü]0\x000cqSæ\x0018ùÀ`ÞßèwvE\x0000%°ÔÓ«(´Û\x001c­v)¨#JPà9ðÀdYïö]¾\x0018^çÄ7Â(oðXcgh¥/eÖyn\x0007\x0002Fqê9<0s\x000bï1*»JÍR*õ9£\x001aIÚZÃ^ÙVyrhceç·¼ÛÈgÿTÖ\x0007\x001fí8×qjÃ±0)ï*ØÒFð\x001d#{iáMi\x000c
_ÃØâJö³Ë¹ªIÍXÜ\x001d·ZYj\x0012ìYô?QI	\x0013	\x001c):
áØ'2º1|Ó©=~2+6´Ë é°íàDJEå\x0006zÄØåPÁ\x001bÎ\x0016©{\x000fØ¢X°»¹G\x0016¤ã\x0007Õ8C:}ü0r@\x000f\ë(¤\x0008Dò§]×ÜC¯5\x001aµ\x001c¯<4Òp?m\x000fY¸OGÔã\x0008Ñ<\x000fMè,
Ó?Ýyþ(k+\x0003\x000fÎ4QÙò©,êÆh$À«ÒÉm÷ÇÍßLÎ"£Óás;ÒÈàîÛð½ÚÜêu@K{ST\x001dºg¨F\x001f=$ëðp\x000c¬toyò)keëÏ'*Ç«æVM\x0012¥\x000c~³¥98ÖÍ±[á`ò\x001b¦>\x001aåè\x0005@\x001cCSá;ØÊÒéò·«\x0000Æ\x0011ëñvt|²ÌÂÏHá4±aü|Ü­_F
\x001c/Yp¤Û\x0019íÐî¾Ls¯\x0012H¬P\x000cïw¯GHe\x0006>@ éî¿
q»üBÿø|©2ÊÉw½J¥ Ø\x0004zÿAþ\x000füîN\x0013¥2ôi^EÝV
\x000fÇE°\x0013¦>$ÉÌQ'NÑi{ÔÀ%£åPò¯\x0003O{ã#|xµ·>´½5Zà»\x000eSåD%T<i½ \¾\x0005Ç{÷fUA'MD\x0007V\x0019\	\x001b¼kG\x0006F
!eàå§ïÖí¡\x0014ûÊDT:e§XzJù°ËnJîk\x0007Ü½Îtp²ÓANº\x0003\x001eZó^Áýö\x0018\x0005eSw¢·Kt\x0008\x001f¸\x001f"Ã×msõcL;\x001fòÙÅÔi7\x001dôå \x001fÄ±\x001aî75câêÝl\x000f×Ðµ×àêÔhrÛ·4G^\x0019cüî]`\x001fºÍl{ <\x000cÝ¾üêË\x001aáë7ó %/í
`Ã\x0005C¤}Ã?4.­Û	jß\x0001O\x0007\x001d[\x001c_²´(z\x0016'ÐTC'\x0006/egC§\x0015çÀlR\x0016ÿ3G1F/\x0010=\x0011à2#7eck]¶g\x0000§	\x0001
GU½Mç
wrE÷ÛÌ%O°«\x0014ÜØnþXyr\x001ck\x000eúÛÙ÷8\x0014«\x001f4 ÊµrÆh¥ó\x0011)÷.m|Ìô÷?& 	>Í\x0019Æ\x0016\x001f$Í¤Ì´'ecQ>]\x0015\x000c\x0008\x000c¦Cú¤à9b©z& WîkCôÐ¹¼ÚëFz«oîIá¹µì6£\x0003êY¡ \x001c©Û¤Iñt6R\x0002$\x001d\x00079
2<ÆL\x0000B>Ûï{Þ(Tþ\x0007ø"E\x0001üÞBî¯qû¾QÆ\ß\x0005¹u\x001eíÁ§\x0017R6 jÐàm[Âa=\x001bGV%8&¼µ¨`TñT\x000e±\x0004¸u¢Ñ2\x00002Ä\x0005ßÁÕÂyéà¼áèXzÖ©¸6NPÞ*
\x0017\x001838\x0011h¢\x000eì(·öê0ÿ8\x0015õª\x0007a¼öëtÒî5£\x001b}çX\x001c×±§ö\x0016WÊwíüà»ðÁ2l£\x001d\x0006òÞ_QÞï¥[;ÚãÀ^\x001c9\x0010í2¢[^\x00057"\x00182: u*\x000b\+_ë¬]ß\x0015\x001fÊë\x0010ÞÒ´]\x0003ÊúY	¿Ñ±Q]qIû¢×yØahAó:âVapfm9det\x0008?Ç\x0010:A\x0019=ÓÑ\x001arèvÎfët[`Ïèá×<'\x0013Çëse8ËÆù-¿?\x0007\x0007í?
ì]t\x000e'õV?ñúþ»á\x001b}§oèÐ6Ø\x0018í`rtéXîúD~éÈ\x0003ß!½v;
þàJS"ùL°\x0018îjNr¢Å1üµîóaø>v;õ£¤4ðK\x0000¿êp\x0003ß²/\x0017!Ó§ÏçñmË%\x0003,ò·j~H4ÌFäC;q\x0011¦úëüÐ ú|ûv"[z\x001b\x0014'\x0007çOðîÁc|§§«·hÚ\x0003Nèä;\x00022<2|²\x0010\x0010\x000cÏ»\\x0010®ùè¹ú¾ö]_ÙÚoTJ\x001c\x001c+7zé¬aäPÏï[GºÂm¯\x0010&*¨1\x0005\x0017aÄ­Ñ\x0000Ò\E¹0½9'ax=OV(ý$9\x001fd×\x00085\x000bßgèZ\x000e$
ê&·1*ËzÌ\x000e2\x0002½Æ\x0018jeG\x0013\x0013E®óX¢æs\x0008ô®kDjÇ±Æé³Î®Ê¢×3|ÏzÊô¦\x000eô^\x000bi\x0017³X0È\x0010íxåþã\x001f#ø=Ð
_\x001d\x0004GÐWXP68Hy\x0017ü[üµ7xÎ\x0010¤ZÛ(ü\x0013	\x0013ìL,íP\x0014-³\x0013ÓÒ	\x0016\x001a}ÂÁ÷*e>Õwá¹Ï0Ñ3¸\x001a®MgDvÛ(\x000eØÊÂ\x0003¬\x001acà¬£wMy<Ý6\x0017:Ìåg;£`xÒçýÛt¦Gßªàùnv}R>\x000cvø^M\x001bÝç:\x000füÐ.EÔu
\x0018'´\x0013\x0004£Î>wôÇ\x0008h&oÐsDòKrNe868û^ÙÇ1áa¿üYoò+\x000fYD<1¹ÒÔÉ\x0004\x000cýá,{R¯CõØùv¢¶à¿2g\x0003èô\x001b>`Ñ\x0019ÇãÅ;\x000c¯Ó #ùêÈ6ºL÷f\x0002Ê
©Ï\x0019W6q&\x001d1\x001eùùä4Ê\x0003¼\x000bÎrðÒ'£À{!.Yw6ÃÉz_|%O\x0007¹Á½ÁU×{^fý#ÌÊ·GÎKº\x001cë]\x0012¹ï°ÝµÕe:¥ß«KøâX=t\x001fºH0\x001e<ø`þ¼Þ»L¡§:uìvÐÝù­vPF;øìà>ÕAË­Nçfökh\x0010\x0019¡Ì\x0010\x0004\x0000¿W°¾;\x0000'XFå \x0004×(¨ìí=C\x0002MþÚkc²I0üvîì×0J­é5\x000c\x0003&áO	ä,Ó
2ÓI\x0015\x000c3«:½¾¨dumÌÒB©´Ý¡&æc¸µo\x0014;°)\x0011¦×¹'æ4\x001bÎ)î.9]V»\x0014$'úg¨2Cjõµ\x0001ïN¥èj$ê«[åR\x0000z
Ø
nðn\x0012=8îdGedX\x0005Ù\x001c\x000bo\x0015Ï§¶ñ\x0013Ý{*»2U\x000cáiX\x0003wp@¬²$\x000c®Ø\x001eË_÷¶\x000e·¿u¬c\x001c¤\x001fç>\x00131:\x000e3íÉ·yO\x001fk¥úÝ\x000e&ÆØÝ²RNôµ:¶W,\x000eËwø\x0010Çóìîó8:ã\x0008ì\x0019\x0007KLë£Hp:\x0004ËäNgrpû¢+åÇmëE÷Æ¨v8¯{\x000fÌ®ÆH»&\x001e%×æ\x0011[\x001b sVóÏÛð ÃÛè\x000cø	4Ó\x0003ôlG´N\x0013ÿÉªÌ±GN{lcêHcq¤6\x0010©s{\x0018:¼°28×±ÔîÀ¹t"èuà\x0013þÝ\x0015ã&KÕqísRt%\x0011\'{!£ñ\x0019£Ê)ÏMèÜE¼Í}fx-0@'úÞ½SfÒ\x001e\x0005\x001eÄfuÃÈ\x001f¢yeÁÓF}\x0007\x0002Îá{Ïündï»4\x0013ý\x0000\x0014Y?ÈË:¿ûuÒMQæ·`l\x0002\x0015|ENÎìË
]Wgæû§ñºÑ\çáÇå¤ëD\x001bË57\x0011²È\x0003ètmË«»°ÖcäofA§wúg\x0001w\x001c¢¼ßXë(÷(ë(¬Þ\x0010a\x000eJ$)¯¾¨\x000fÂÚhï6:	\x0014æºN\x0001|ÂM/>ü\x001eF/¡\x0005JÁÚøÔU#y³¥ÓÃsÀG[øâÔó*7kÑ\x0006\x000fÃ\x0001\x001d@ñª¢\x0007>ê\x0010\x0001g\x000ct^¯â÷\x001aä:\x001e<{¥\x001f³(}Tp¸n\x0002¿©\x0010\x0005vSKÜIRwî«íìüÞ³u\x0003\x000b\x000eK\x001b	v\x0000ô\x001aÞã\x0014ÃÌ¥\\x000eV\x0004¨.z(ÛêÇ\x000eCÑ\x000b®÷\x0019ÙûÓ\x0001ÞêÎÒàS.JgðKr?åÉXYFõã4&úÐyq¢ð'?u÷Dë"E\x0006îùsrêð¬é\x001fòÙrx#T\x000e:K¹Í\x0019:¢\x0015-èt S\x001bK÷F®­\x001cCùO¸w\x0012\x0018Q5¸ÙSÔmÊ´ó:úÇøc´&÷Y½vÏuðñp\x001câØ
Ü¼äs°3¬=m´Ï
ã<\x0010«=â\x0003Y\x0007]Czé,¶-mWoÒ¾vï$íkÒ4@Ë\x000bío}¶ç¥ä¿Þ6»²¿½ñ\x0012K`D}6óêÕØ-=s­\x000bùÉ7ü¢ëâÓÆt\x0008\x001d~£³ÿ]{_'¢ëiÄ¿>\x001dX\x001d\x0011ÛP½@ä@Èr+N|+Oúr:=i
Ê\x001cÕ»ú[\x0017v«Û}²©
\x0019\x0000ò&"Æîk\x0008¹6À5\x0008Ä¯	\x0008C7?8\x001b\x0018#ÚEµÞQ^ÆDà^[\x00006Fë0Æo\x0004µ}H#áíæì@åÙã8ÕÔAFg\x0008r©;K8à´yØq\x0014s}\x00041¨3Ð¦hZîm\x0014\x0019î7\x0014¥]ÈlèF§ÓdÒöÒUq
SCòý)¥¦ôáÇæYôò®Uy\x0003»6yaõ·Îæ<\x0019%W6|\x001dü\x0008nð8CõÐNIÐÇa@b\x0015Ùç:8¹9Ê
5Æ÷\x001aSÓ/Q^ÎÒ§^vä;³½Xí9gõÖ((ÓµÕ\x00058n'ËAéLÜÓÉ4§ÜNj\x000cHNÎð¡á¥M±áG'ÔTËL´­·©\x001då'Ún\x0018\x0019Ìî¡EÔ\x0013\x001ey^½y»ðÐ\x0016;\x0005É¥úÑÈòj
Øõå'>Öé\x000eVyí+ßeC¡>&ÑZ£íÜgêËQvÙVªº\x0013\x0000p¶\x0017'«®{hÔ¾cìc:NqW\x0012Ð#pðtþôYd?Ëå6ê*ÒÁ\x0006×!©q¤:@Ç:Vzì]VËg×»%G\x001f¾ÈwkÊÇMÄ¬ìÊÆH\x000fKú\x0003~®ý»¾c¯\x0007ï\x0002\x000fÞëp¯a]ëÝÂf_Èªò.ú´¶êºKÞè0\x0013}\x001cêÌA mèJî6ûeÈ\x001ay.m+~\x0017nms¯5"Åª-
áXA^Wt}\x0005Ý:Aø\x0008\x000e5ìâ|ÏdÂ1\x0018n{ú\x0008\x00029ä0
I0NoËñ\x001d4#h\x0002ËüîÕØ,ub\x0010\x0011"\x001cor'
àÁ\x0008#äYS9Ã%Ü\x001c\x0007;¸.<=Õ£G³q\x0005\x0014£+\x001cKÓÒ¨>å­cH\x001b\x000euæ©qB¢Öâ\x0011g¸÷ýîcùì;±\x000cÑ3´j^6×VIÁB»¡g¬_¿Þ\x0010.
f
ÕÙûð°ëú\x000cá&¿vKåu:\x0008è0âu\x000c`¸>ÎjåÇ¹?>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/media/cache/listing_medium/uploads/listings/images/7cb5b69b187d583e3f98110344a42826cd265fcc.png](https://lemarche.inclusion.beta.gouv.fr/media/cache/listing_medium/uploads/listings/images/7cb5b69b187d583e3f98110344a42826cd265fcc.png)
  
  
  * Method: `GET`
  
  
  * Evidence: `<?=úæéÉ·Ï\x001fýøújß'¶\x0004(\x0002%	$F\x0016¥&(´&\x0000\x0000 èÜÝî7÷¹+ª\x0000\x0000H¢-\x0000\x0000¶(\x0002hkÎi]\x0016\x0004$Ñ\x0016$AÝ·Ííõæö~u»}1·7ýÿ©\x000fç¯tî¶ýª;/_®ÞÞîXÀ\x0010\x0011R@\x0005--mµ5K[\x0014P`]±\x0018\x0001ªfKI(\x0000¶ª¶:§v×îÚj©êd,\x0005É@\x0000´Di%\x0004\x0004	Â²\x000e\x000fg\x001f\x001d\x000e\x0007·ë\x0004\x0003@;A[É\x0014\x0003E\x0011\x0004\x00000\x0000@P\x0010\x0012D2$C2$Ã\x0000A\x0001@\x0001A\x0014\x0000Ð\x0016\x0000´\x0004@;íÛfÞwmÍN·m³íÓ¶OZK&õdÛwmQE[E\x0001\x0000mA[I\x0000\x0010\x0000P12°ÚnËáÝý¶{ùüÉ§ßÿä~Û\x001cø*¥Þ>ÝýøÃ¶}·.¶ö}wß§ÓzpXVí\x000e\x0000ÚJ¢ª\x0005fwD\x0012ß}øèºÝ¼ß¯Æ\x0018Æ\x0018Nëâñxö|z0ÕO÷W×Q\x001f\x001aoÓé(\x0019îss¹Ý½^o>><z»\}xxð³\x000f\x000e?¬nsÓV[\x0012Z\x0012Z\x0004\x0005\x0000\x0001\x0014	\x001a\x0014LL\x0015(\x00014@\x0012ûö}×\x0012\x0001\x0000\x0010\x0014\x0000\x0000m%\x0001\x0000U\x0011I´µÏ*(\x0000\x0000jw÷íâ²¿Øî¯þÇ\x0011¶ÍW\x000f_YÇ*hW.O·A\x0000Jh'J«­9«s*$\x000cLu,\x000eË\x0004\x0014íÔN\x0010\x0005 $@U[:mûf»ÝÌûVÑV3h\x0011I$@P!\x0001\x0005P\x0011%Î§Ç§G'o¯ï\x0008
ª\x0004\x0005
)\x0002\x0008\x0002\x0000 ­$\x0000\x0014\x0008\x00002bd¨\x00182´Ã\x0012@\x001bJK\x0010@[\x0000m\x0001@[mQUmµÕNsNmÍ9uNsNÛ¾»oû}s¿mn÷»¹OfA[mi¥Q\x0014I\x0000@[\x0000\x0000\x0000\x0000#±ïu»ÞÜnW¯o\x0017_^}yùâò~sÛ¦fõúåêËëu,Û¶Ù÷Ýa]\x001dU\x0004\x0001Ð\x0016@EA\x001dÅ/¾úÆý>µ\x001cÆâ´¬\x001e\x000f'\x001f\x001fÎNÇ³··«ýr÷õó\x0007£¼Þ®Ö\x000cuÛvûÍËÅo¯Þn\x0017\x000fÇ£?ýêg¾~|22\x0000hµ5[mU\x0015³ÕVÑ@$\x0000D@ÖlM5ÕTÅ\x0004lûno\x0015\x0015\x0012ID\x000c\x0011\x0001\x0000\x0000I\x0000@\x0000Ä>wÛ EI\x0002@+F¦¨5C¬¾Ün>¿¿x½¾y»ß}¹Ý½Üv·=\x0008¥J\x0000\x0000¶Z¶´\x0008e\x000cc\x0004Ö¥DT\x0000\x0000HIQsNû¾Û÷]÷©-:«Ýµ\x0013Ö\x0010\x0001\x0000\x0000\x0005Q\x0000Ãz<yz|ôôøh\x0019\x0003ÕDC\x0016\x0001Z\x0014E$\x0001\x0000I@\x0012Ð\x0016!\x0001m)\x0001!!±Ê\x0000ZS)J\x0000\x0014Hh%\x0001mA[I\x0000\x0000\x0011DCK0ÄHÌY\x0015Åì4Õ6w2[¢* Z \x0000\x0000`¶ è¶ûÅv»¹6nïïî¯/æõÍÈêt<X«ÃáÁåò\x0007ûU;EÜ¶»mßÜ·ißk\x0019\x0004\x0000\x0010UBKT\x0012#ñp:úúéÉ\x000f?Ù÷iÉðp8x8\x001e}xxôx:y»oÞ?¿\x001aûõxpßvÇuÑ}:®}îÞ·»ÛvWgûÜ}x<û\x001fýðåÅûm\x0012ÚH\x000b@hIÐ\x0000H\x0002 ªJ\x0001(@\x000buYÔ$\x0014\x0011	#Ãì¤\x0000$\x0001\x0000m\x0005RE\x0011sÞ__)@\x0001hÁñxp8-Ù=­O>äÉÕO·WËýÍi=ãÑ6WÃ \x0018\x0000\x0004(\x0000\x0000UZUPÅÔ95Ã\x0018C\x0004Àlµ\x0005Z-@\x0000\x0005-{«­¢*Eêvs´\x0004 \x0002\x0000

ãañx~ðôáÙá¸ï7R\x0005\x0010\x0004\x0016UA$\x0001\x0000\x0000 E\x0015PUHT\x0010kRR\x0000VQ%H\x0014\x0000D[\x0000\x00000\x0004@\x0012c\x000cKÙ[£µÏ Új©P¦ª
\x001d\x0008¨I\x0007	)\x0002h+	H"Ð
tzÿüÉÛÇ³ãÁír¹ûðpöôôµ\x000fO_y8\x000cë6½¼¼Ù¶M;Ý÷ÍeÛ\n7ÛÍ>§\x0008 AI( Hb$Úz:\x000e«û¶Z×á8\x0016?ÿøä«§'#C÷ÍqÄÃ2dÄ}ßÌ\x0019eõp8x¿Ý¼]/.·³ë¶Y®¬ËðÝW\x001fýúÇ\x001f]ïw{K\x0008\x0014h¡ %\x0016\x0008"ª(¦*\x0000
"	-"
\x0012Fu\x000cSÜ÷\x001d´\x0005c\x000cCÌÖ4iADÕD0;}ùüB\x000bv\x0002ÓÃÉÇ¯\x001cÎ»ëåQnåèº½ú|ýìa>:,qg³\x0013(	\x0004@\x0000\x0000NíÔ\x0016\x0005mµÓ\x0018Ã\x0018 ´è¤\x0005\x0010\x0014J\x000b\x0001D[sîæ*Ò­Y\x001aZZæ¬Ù\x001aHH\x0000\x0000	\x0002±,Î\x000fgOÏOç£Ûå\x0006Ú
¨$Ú\x0002J©R\x0005C\x0012m%ÑV\x0012@\x0000@\x0015D$\x0001kE ¡A5(\x0000Ð\x0012\x0000´\x0005Ð\x0016$\x0001JÅ,sN\x00054\x0004\x0011\x0002\x0004@AA¡P\x0011\x0001´\x0000\x0000\x0000\x0000\x0004\x0012TËûÛÕË?çnýr³¬GçÓÙi=8®«ëûO?}ò~½ºï»ËíæËûÏo_ìû4g²Å>'\x0013H¶æ¬¯\x001f\x000c·ín\x0019Ã:=N~öüÁÓéòùíÝ¾ß]\x0007¯/7û¾K¦e9ZÇb¶îÛîõvõt»éùüèçÏ\x001f}ûüìÓÛËv£h\x0015-IÍ\x0010Ñ\x0002T\x0011A@0RÊD\x0001EqÛ7UÄ@\x00111Ä:19«&\x0019Æ1\x0016Á6ws§\x0018	ª­Ï/ÍN (\x0011\x0006ßüü£ú\x001fþOÏÞÞ>ùüÓ÷Æ6X¦k×Û«½e?Ûæz@Q\x0004\x0015¡\x0000\x0000(ZíÔ9µØ'­e\x00191\x0004Ð2[UAUS \x0004P:iÍ}Ú÷i\x0015UÌV24!\x0011
@@\x0015\x0000\x0000\x0000¥5Æâ|:zzxôðøàõó«Î
 \x0000`Ò	:wm$\x0008\x0000&Ú©\x0000H\x0000X\x0013@\x0001"­@+\x0000h\x000b\x0000\x0000\x0000\x0000jGR\x0008\x0012\x0019CZQCea \x0000\x0000¤D\x0014\x0000\x0000I\x0000P-\x0000Öû«ïýèý\x0018sÛí·Ýùüè«§¯\x001cÖápX}¾\¼|þìýzq¹ßÜ÷»m»»ÜnöY÷¹\x001b#NëÁm»\x0003(!PªÚ*¾~~v\WI\x001cÆ0\x000eG_=>z:>8E8¬\x0007/ïï×7\x000fç³ózðx<YÆ°.ÙºÜ7ûîõr5÷iÍê0ç\x0007§ÃÁmßÌNEÔ\x000c\x0005(\x0014\x0011´@\x0008Á\x0010-Q0QL\îwËXLS\x0015¬cXEÄHÌV\x0012ËX-cXÇ\x0002f§}N\x0004ÌV[\x0004õþþ®³Phk9\x000eñg¿ð?ÿK§Ã£íù;_\x001e¿ñåó\x000f¶ýj»½z¹.Ý°\x001bØ\x0005TE(\x0000AÑV[³ÕYeNænv×î\x0018cH\x0002ªfKiP\x0000´
ª¹OûÜmÛfÎ\x0010Z$2e\x000cc\x000c\x0012\x0010@\x0004\x0004\x0004\x0000\x0004\x0008ÇÃÑóùÑóã£\x001fÆ°Ï]\x0012m%Ñ\x0016´DL2m;¬\x0004\x0000\x0000
 h\x0001H\x0006u$H\x0008:\x000b\x0000Z¨\x0002\x0000\x0000\x0000\x0000\x0018\x0019²,Æ²H¢­ \x0018a´$¶ãaµd\x0006UP\x0000m\x0015\x0001\x0000´\x0005IHh\x0001´\¯wß_ßüØ»mÛÓóó³¯¿úÏ_Û´Ýî®·Ûvw»ßÜ¶MÕ6§Ëý.cX\x0012Ë21dß\x0005\x0010@\x0015$1Zß>pß6Âa]F|xxp<\x001c1lûtX\x0017Ë²á¸\x001eH\x001cÕHì­Ùiß7û¾{»Þ$±Þ.Î\x000f\x000f\x000fÏ'ï·«Û\x0012Z\x0000\x0014h¨\x0000Ú\x0002 `4v\x0015@p½ß­cx8\x001c½ßïÚiYVÇe1ç$\x0003Ó2ÓzpZVuuÛîÞï7VTC[AD\x0012·wÛ¶YG\x0014Àñ¸z~|4Æj,\x0007§õdù°z8>ÙçM^¦×÷?¸Ý§mÒ\x0002\x0011A\x0000\x0000\x0014PÖlÍNNsNµÏÝ\x0018Ã!\x0000-­6\x00140"\x0000Å¬9kß6sßµÐYmi%ÃX\x0016ËX$D\x0001@\x0000\x0008\x0000\x0000°¬«Ç\x0007ÏÏOÖãjßv\x0000\x0000 1Öá0Vû>tÞhU\x0005\x0000P´\x0004\x0012M¤\x0005-I\x00041¬\x0012A¡UUT\x0001@\x0001\x0002\x0000\x0000\x0010$1a,¹.\x000csN{+e\x000c `¶f'	(\x0000 (ª\x0000\x0000$\x0000\x0000\x0000à¶O÷}sÛ.¶m32lïwßúì«§WëÓb]VË²H\x0019"u=x>?x<MÓÛõ\x0018\x0002b Ú\x0002	­¶Ö1||x\x0014±ÅÃñä|<x>=ZÅ\x001cÜï7×ëÕ0\x001d\x000f«\x0019îû®­%,Ã²Z\x0015±wºîwÇ}uX\x0016_?>`
  
  
  
  
Instances: 2
  
### Solution
<p>Ensure that application Source Code is not available with alternative extensions, and ensure that source code is not present within other files or data deployed to the web server, or served by the web server. </p>
  
### Other information
<p><?=OáP\x0008
,q"\x0017 "µ&TCE¾Û¼ÍÓ<÷\x001c	èyv&|Sg\x00082ÍG\x0011Î1\x0016×ñæw#¦|ö¥wYºó!ù\x00080«¤Q8	P³Â\x0004ý.C\x000eicÄ\x0014@tµÊÙuÁ\x0013å«\x000cÉk~\x000f>F3$î³à)\x001f´</p><p>GÒ\x001b^kÚã^?AûM\x0008û¨ìîâýðA6\x0004É¡Îî8áóxcè\x000f."ô{¡	,|\x0019>y(0^
ïm\x0007LßÕQ¾øái~O§2·«+òÇXàÐW_\x0006½çv\x0006ø®ò;×\x0019æì>Î¹âÕt¨ø¤Í\x0017\x001cð\x0010qw\x000eã\x0010ó7»=­­S»vÿLd\Ò\x0017K'øØBv®áSØ¶á¾Ni?µ¡=ð×A-¾\x0015È9Àt 	Çè¤kxµ×\x0017\x0006£)¹g$¥}\x0011vða£S¦¬ûÊ.Ú\x0000Mù\x0003mÕë\Wgè<7g\x0015X©Z\x0007t\x001e?lgmÂðCòh\x001d\x001e?Ñ|\x0013\x0006Ì\x0004èì/:ê5Qº§¼à5¶0©\x0015m;¼!aßæ7@6Ð&P²S\x0019¸¾	þ\x0002§±{O8y\x001dûä¢WN^	=Ëf¤÷$i?°¼uóu&m¤óè8Zð£ú\;\x001cûÂ_\x001b°Âomì¤\x0010\x001a¥\x0006vóìÍ³\x000bê´ÿîÝe¨÷êÉÇj´Áhsùý½¾$\x000c½ÉÜFuûÐ7øç\x0000\x0003ý9´\x0008Fq\x001c§yÏ$qT<8»QÈQ"DQ¹*ðûÕgC·D\x001cfO¾a¤Ü\x0002\x0004;´ã»\x0006 aò\x0001\x0002\x0018·F\x0000&&n¤á¾²°W¡ü\x0019"vv\x0017~9ýC)ï»Ï86ÃZ\x0006g\x001dè(ê8S×\x00191ZÕEã%U1ôa\x0014¼\x001c×Nô:B\x0001g
\x0004?D\x001c¾×±¸Çq\x0011jvIÏºNasÇ]|l\x0013Þ#Tu´¶\x0015 >­3Ûë~µ©
¸8´§3é2ðéÁ§¼oläAÓ)åÀ\x0013Ã\x001b¿}9Xù]CM¯\x0006o\x001cÍò\x0012|mkoÏtîALNVã¤w8>¸)ç±ÌZê¤ÚÑ\V1pìD³4opô½F\x0017\x001eýö»ûø·¼ñ¹N|å¹zÑßÇ@Ô[Þù¾íú^Þç¦hÌu\x0007Úíá9<NüZnK²pEëê¹{K+\x001e-\x000c|Å\x0014¾:d`Èm2CDjø\x001c/\x000cwÒBÏðô2:·^|#Î\x0004p^m\Øl(²Õ\x0011|óÍ×Å>ª\x0005\x0003ÚÐÖ:Å\x0017Ý,ÚG&9ÈÏ\x0017\x001e<|t6ò\x0008Ð\x0007l\x000fMýÛß*\x001fíé\éSº¸Ìò¶£¦üí³ÿûê|»H¶KÀä7SQ\x001bÞÚæ¿þþ,±£SFn\x0013¯nàõòÞ÷uÄã7'£û££kß`Ç½wT·ú³ºG7ÕÁ\x001dõÚåí½ÃÀ×ÖtÀ\x000eõ91ÏÏYÍ-¤Ò£G\x0013÷[<ü*Kõ¾¦\x0013\x0000\x0000B½IDAT\x0013D\x0004ã\x0011E=OWú{ª)ÄÊ+xúåM\x0016zcJ\x0015\x0001yí¹£ÄæÞ2´_R J\x0014æµ'È¥nÁ×tMJ\x0008Âí.î
\x000eÚj4«tþmO¿N\x000cØuL1\x001fG¸Ï¾èd\x0014\x0006ë	åfØ=K{Ö\x0018Ý\x001f1°µµvÝ÷>³ÎÈ¯\x0018\x000f\x000fPV\x000erk0×Pû\x0019üEØyqqGÿâ¼ÃPF;£3D_ê,SïÚP;<,D6Ê6$´'«þ\x0007\x000f´;A,3\x0014\x000efâF\x0016³dSYÊåTwù	'9,4²'±UÙuj«\x0003\x000bGä \x000cz\x0007Æð¾
\x001c#Kô\x000bÖÒG~«k`Âiam²øâÓ)cÏáZëäó}Ù²FTG5Ê\x0019BnG§ºööQËvG×Ð]Óî:W8iËuôÁÛ=².~Úô\x0012JöÎtBÄá­¥dÕÓyÌèÂÂÿ}9f\x0011y\x0017ê\x001f[a#tG{pðtâ¾Jä§¬Ç\x0014õÁ]¤¸ø-_86¶n:ËÖè\x0019üïÆ^L\x0008ØÒa«\x0003þ*ý^5<·¼É¤Ø«W¿\x000eé\x001fí Ã¡m\x0007ØÚõÛÆ*r{¿ÛÙ\x001dúm þ.2<¯ÛDÅ6V\x0019¾</p><p>øéÏ`u-\x0018«Î\x0018
º62\x0005>°²Óq÷GàÑsu­fÀ;Q;á\x001b_IÜ0³§g°E\x0017oãÌôõÈ\x0001Ã¡jàÇ!q8r6\x0014o¢\x0015Yx{\x0012¤:\x0013Yaz±ëå@e*¤\x000cMCïf­\x0001ÁIÛ]LÙàï®ñJ\x001f¥ÚmëÀ\x0007{£¾1N\x000eur(Ö\x0001ÂXÖ!qÜí½Â\x000f»úS=¯
\x0019ëHf×¬qì\x0004¨C¡@Î ËU\x0005o\x0018«ã(L=lï\x00050·=dï^Ç\x0008grÒî¯1(³øwêRÔl©±&ê#ø>	\x0008ÿn?®\x0011\x001c^OÇ4\x0013\x001d\x0013­3^' =Û¾á¥ó\x001aÿu\x0008ðû/s6Ï&sÃ°Å\x0019¾ðtl~\x0013Ñ\x0014Ò~ê¯³3C÷´5\x001cA«ö\ß	\x000cÆ\x000f¦{hZGµrÖ¶céõ¹z»F«þÒ´9üÕï-ï\x0013¬®dÁçüÖ6|\x001côk;ìÕ¥¡\x001b
ãü£\x0013Û©¸_\x0005ÖÊO'÷9¯þ9\x0013fì».ö\x001fÿéÎï¿ù¶¨ïÂ«.;\x000c¬I»xâèUøhõØµBlT9c;\x001f>Ûñ\x0008ßuÚá uÎ_eö\\x000e|l7\x0017\x0004ãÌj[j¼d\x0006û\x0010%S!|ø!Î\x0004/\x0016åÁEÞgeGxý&»/áàK`ì¼òõ \x0017½ÖÎèU:ø&¼êÄ[ðÓFyöÑb²«Ë´í\x0002}êçÉ}y.º%ºÕ'áè_:ØkV\x001aM\x0007_z²\x001d\x0003¼µe\x0015\x0013¾x$öÏþK`\x000b8Ð\x0018GZ®D±wMá\x0002¡Æ\x000cBC¼\x000e"Ükä\x0015ÂÜ$yêû×¡C\x0004\x0010&M\x0012x\x0008¦¬«¼à*#¬Bíç:\x00085ª¼aÍq¾"µ\x0010j\x0003gr¤@zÊ(c¾qe^èÒI¬±k×\x0006\x000f`s.;ã^Æ+\x001f\x0018X¡Î\x001a¨º;á¡_yðË\x0017N°t'<½\x0018>ãºû¬\x001e\x0005ØáØ¯q=8¡]}\x001cumkov\x00155ÅÓîeK²éQ\x0006¯q\x0014ã)À.A\x001b§ÙÐ\x0018
zÀZZ6ÊÇCJå¾6\x001däF8»N¹á7\x001b1ÒOyLDÛø</p><p>¶z~¯£À³uZãðf¸\x00046ZÇ`ÎdC\x000c¢¸§\x000eCÐ6z×@Ý\x0003eª®và\x0005cõÊïé\x000cfrHY¿\x0007ö¥cØr`\x0006Øä¯SWþ÷V\x001fsoîÊ^=ö±íj»z\x0007NÅ\x0011j['ÐÜ^y66D9µÇ\x000fä\x001f³çýyxAµ²Ù«8=N²[?Æp¿Lú=)G20ßW§
½\x001fwAýÈº£ÈTôd(:úé
Á?\x0014Ç?üþ\x000f}2
á»~B\x0003Þ>I}[A\x0011¾\x0017 ä^(h4J>t\x0003¯ÆW\ôÚu2WÎ®ôîsFìO{\x0016ó[Ng\x001d\x0019ä~ÓÇgpòðWÞ*\x0017Ç¤\x000e6×+\x00052OÀ
\x001f\x001e¶\x0018ý\x0011Ô\x0004\x0018:ùtni\x0007ïi(Ü&+³\x000eþÒððYF\x001d¶ÏhM].À\x001d<¼û>+\x0010è'\x001ey£â kh\x001b\x00032\°(77ß\x0004©zö08?S\x0011\x000b\x001dÍ\Â|Pv/'ý\x001d~xªèS\x0018²9\x00043Þ}"	¿)\x0006Fú$äUDÄh×g¿s6\x001cIz\x001bÑcvÙ¢îÄ&ù\x000c£`U)GAõ\x0012ð</p><p>×º\x001dì\x0008:½\x0008\x0006P¾Y÷UF;Ö8Á\x001eüÆ¸\x000e\x000f|Ù\x0008MCW8òÒ`nä\x00052'oBè=%sa8(*3ÍÝa\x0013²\x0007Ö6½¸Àw¢¼q\x000eåÃU'1ðÚHi\x0015S2¥üÌì{;¦´³ÊÝQ´I\x0014cs¤++40ðydt\x0012ø\x000cBÝ*bð\x0003ÏçFZëëHvy\x0018|®\x001d*\Æèu²pNd#\x0003ü]'MïèÄ,H×\x0001j²^/¸­£^g.¸¬£\x0004Çá{p{gÃoKVÐ£]øçhZ+¿7cx¢Ñ\x000e½soø24¨·º©üvP®¹7º9:ºa±{ë¸o# èmâ¬à\x001c¾³\x00140ü¨á\x001aýÙ/øI^û£s6ù3ü\x001cYYbv7NPÛ¥%r­\x001fC¯åÏë1úàIlíÌÚ\x001bê\x001bb÷·ïnu\x0004
è©#Ë''\x0007gÎØHêIÖ{²-eÀuo"Â\x001dáLî\x001e¾Í\x0006&cÃxåò\x000fÏÇwÒ2eñÇçûàM\x000e/¾H</p><p>îË\x0017w~ø»\x0008ðOig&Äû\x00188\x0014HUîwÖwZM!z\x00149sòø\x0000n'ÍÒéè\x0014rax´÷\x000eª> )ÅÜß\x0007VN7ývÅß¿ÿ{aÓ_\x0016]Zãê\x0012\x0018n\x0012Ó\x0013¾\x000cõ\x0019P\x0003\x000e\x0008U@vñ®¼(ÊFmc\³&p¼?å'e2ÄÖ\x0008ÔÞÙæ\¾U\x0000à4³\x0000?=ï¬¼\x001f÷¨¹!³ã³ÕC\x0005ÍËF¸MJç\x000f£kØ)«]A\x000f|­Ãäþp3Î£ÈqðX\x0006®A \x001b\x001dëØÜ§Deü¹gø5õ¹v"ÿåç\x001fëÜÍÐ[_Û·­\x0006G\x0017\x0007ÖùÅ±W±C\x0017%µÈFµî¯aGs×ÌÒ¤Ø\x0019\x000cGÀ\x0011QÌ\x000b1,¸-=kô\x000b2Z\x0013¸k\x0011µehSG¹kÇ\x0001ïà6NJ®uG0íû\x000cc£Lp6ÊÝâ93Ùyeë´äô~­3\x0013\x0005i\x001fnëÄuÎ`/¾ôMÛ\x000e´Á*ïÞÊL½:cð`¬A«f¿AR>©\x000b^u*ÇòÐ÷ÅÇµéPg4\x001eÇâä~ñm@`õKpÊ§¥Tüã\x001f\x000bþs2Ý4(6ø9\x0001ß
|¢Gz^Ñ5:«^\x001cÐÊfÌ/|ÊTÒÌ\x0003¤½8
ºnýèï¿ù}\x001dâ÷?g	O¢Ùµ=pßÅ1íÄ©kl¬øÇyx\x0012I\x0018C¦r¦ÛIÏ\x0012,)\x001bONÙzx³ò/_Ã¿n\x001aF½qF³!ÊÓäEÓÞï¢÷G\x0019ujOY>g°\x00077ÈdÖy4Óê¬ÏöMÛxÅ9ß\x0016ÔÃ\x001d¿áN¢Kè$oúá;?\x0007?K°þô§?õåy×:àû
*Ü\x0018ÖE9Ò13@Hv²â8I\x00055\x0008 \x0019yÎ.RL/Na&*a¼^\x0019R%+\x0008SLÜ¡Û(æ\SF[î\x0003Î\x0003hÊÚÏÜM\x0013¥b\x0000x¯D\x0014z«(Ð\x0013NeVàt3ÐF\x0001EË\x001bÑ¼|%\x0018Q*Ë8D£\x00046Ë¼\x001a×VQÊÙ\x001cz¸e>þ\«!Ïðg\x001e$ ûÿþõÎ¿þ÷ÿVÞýòm\x000cD\x000eÇ:<4s:\x000eQìÃ{\x0019\x0005\x0007|r]®ÓF\x000eís!¹6=lò\x001cøq\x0012%h\x001b¯\x001dçÆ×`^j\x001bQ­s\g§GUnz×é0ÈÖ«2(0Å%\x0017µÊ¥½íXS¾\x001dYxµMuLåc`Ñ=NÚoüR<Ñ\x0002?<æÌèÉÂ\x0019Ç=Cyð{³ôÎý-\x0003ÎQN\x001b"Ñ\x001añá+^3 ç:J8±zX]<m)£®{ëPñtáÃwy<\x00068ú3Ä\x001fYª?ú¤£\x0011xúLT¶e²E§¸×Z¾ö,o+ \x001fÑi÷6
_\x0004@Öâû8ëÈC;ºÑ9ÓÙ*3N*zöâÙÌ|¿(¿m5g÷x4Àñ³\x0008TÇþ.«\x0019uøH3 \x001dûKçä) #ëÕç¼<Í2¤uTË×>µÀ\x000cÑçYvm	r:yï_|m"JÃÿïÏF$\x001c¤:ðû\x001dÝ.ÇÌðO¾ôQ;#\x00110\x0007Ntd×êZ}\x0000®vÈî¹7ëm»7\x000fÉ,ÿðÔ9\x0001Ø\x000cçÿÞ\x001d®Ø×Ò	\x000f¼ëTn\x00152ÂhÃY#	üøÑÓ¼ãDØÍ{GÂ(C\x000b3¶À Îr¥OïBaì|¦Æ\x0013§\x0016Açð­±¤Rsy¹\x0019%À5</p><p>ß\x0007yÃó\x000c\x001fô¸ïÎSVqàÍÓp1~4Îvcæ¾!Åö8Ä>¡\x0010¢«\9oïäõìt5ë1S\x0004ú9QÍsûÞxä\x000c0O²|¢öI3 ãZ	á÷*½ûÏ?þÜÞÒ=\x001dT!\x0012¢ä\x0014âÊÓè\x0018¨¶V@>Ê\x0013½ÜCÏ:
\x001d\x001eYÈa=2\x001cuHuÇh¿êmz"9¢</p><p>ZZ/ÎBn£ïâþ´áTf\x001dÞ*³h\x0006Íâ)ù
Þ?Â¿ Ñ\x000eª<\x000cMtÁÃ\x0013Þ/\x000e7²ÎÉ=pà:\x000eb\x000cb\x001dw\x000f9E\x000fðftxòªd,úZ§\x0006æâ®\x001d¿W\x000fÛ\x000eÚ\x0018¤~y\x001d&\x001aá1|uÊÍð,ñL\x001bÊÐÉà\x001c¢N8sôó\x000b6\x0001Ô¡cÊ÷©¿\x0010ömC¹'1~\x000eâËìÅiuÍ\x000f?dçC&ôª\x0003·:\x0018\vív
}ü¡\x0019ï/â;Y</p><p>pTÎSn?eÔd§{©¢Ç÷8æy\x0017Ò\x000cã§lW\x000fâ$ºÎ§oh>\x0013rYW.¸z÷.\x001b$G\x000fÈ[pÖ\x0000Næ©ÉÑç	^ºÙIþt"«WµÐAwh\x000bþéäÉL`AÖd±º¼¶\x0002¯ÇL³\x001d\x001fþÝ½\x0007
ëÊKSÐ;\x00110gNfN°É.ZÆÈn¤\x0001¶S\x0019ûIôhôïI1pÀp6NÐGÆwõ~}\x001ahòðîcù1ìQ \x0011ÂLÔð¬\x000fí³¨6\x001cË\x0001)Ç\x001ad7ç°[Ì¹¶\x000c@\x0014eÅDÈ:0âúèÒ§8p8=Î£÷¿\x0008\x0003#!Þ¦¯¢å´\x001dÝåP	ÀÞF)å2<eÃ¸Àow¦zI\x001c8_ÏDh0d|>ç\x001cs¢\x001ey­è"àYk;y7°(BaHÆ¦íÒ+öWüãý?¶üWÙ\x000cBNkóJ\x000c\x0007\x000e\x000eåÑ¯Ó!\x001c§vêxò!Ë\x00187§<;²ëÔð`\x0016ögIUüã½óK³\x0011JÚlZ%°\x001dkÛ;kÁ8)Æë¬ÃC\x0007\ÊçD=6õöü³ãÕqxp[GZ¾\x0007)\x000eN´ýô©i\x0016stã\x0004g\x0004Á)w\x0005Ae
·Qbòkç\x0007á1Áôîù¾F¼zâú8Z\x0011Ã¬\x000c!Ï§@×¹l\x001a\x0007EôT
>NzÇè\ÉP%8ìHcuZÛ×ç¶_G\x0014Ú\x001bCekfqïß}\x0006F¢ÇÁ±«8ð*:úî]ò¡^ô6_¾W,¥ÑTyä/8ÕAÄqþx÷çê:OÆM\x000eF¿ªë]hÿ©\x0006|³ã \x001c¡SYÞ]Ú\x0012©u¸\x001f½]SNuòêÏ÷¬záx\x001e¦óÈ$}ófaø­¾£ãbHÙ®%oî­Ì0\x001cOg\x0014iô0oðlÞ\x00159ØæÊ»zÊN£]Ô\x000e×ÜÅ¬ç%KÏ:çÚæ¤¶{Úæ8]o12"c£=~
~^ '¥PøxÃ¨\x0007\x000fé\x0005=\x0006tzäË3p¾ß}÷·\x0003ÿ¢£tÀÙ\x0019\x001cw\x0018\x001fañ</p><p>Ûû\x0012$\x0004'©</p><p>¹(E¬@r§HU\x00107\x0004n#	Jq\x0003Â)g\x001c¡ØBÌ¥W¢69\x0006\x0005\x000fî!&Á\x0004aÔ«"ØR-°ºµÌ</p><p>þ\x001cBæ LÌ\x0011¹êÙ?e0f</p><p>Coã­0c¼\x001c¼YOþæq}&ÒÆÑìZË*L`)û&ëk\x0019wõ»oêìo¢(}\x001e9Æ¬\x001c\x001aÆ¸'éN\x001dOnfØõ\x0006ç\x0018Ü°\x0013OÃ¥¾/\x001b6ù\x000b­\x000ct\x001d
^âÿ£l`bõÄ:\x0019<XúV¦Á:í\x0000ÞØ³{ôðËà<i\x0011x­\x0003ÑßàV©?i¥PcüÚzhÇ1[Ü\x0019	Dw"{2và«üèâF6psÊ(·</p><p>
æêÚèäy\x0012,Îó~I\x0018£\x0017ÃÁ7M=Õ\x001d¥þ8âÅ
Ì¤ÂÎÒ+£ùJº\x001b\x0019Ñ=å×ñúÎ)é`è4úuXh@¿{tðÃ\x001fj;Ê¡KGeÌPS¤9©v®ù¬`ðí\x0000Ã»Ècz$:Ì#¡?%âg\x000bæIE.9ê_~1<ÍjÈ\x001eÂX6¨=ôÌ\x0008êa'U~È.ml­x»o_ª\x0017]#\x0012åÑC¯;Z\x000cÑl\x0003ÅwO7õÉÅÀ/.Ñ»¥G­'¥Á\x001eéÒèø¤×DÍüÇ¼úzF°F(Åµ#³\x000e\{9åCÉe&7\x0008Às)áÑÔ@ën¢©¤&û\x0004\x00083rdwo³LÞß«Ýïg¯WAÖ¼µál^_\x001d\x001eÛ¹Zýðøð0pÈ\x000cÇ®ßtÉÓ\x000f?|_ú§£Õ1\x000c­ôç¦¡z\x0008èkDÂ\x001cÞZvm,UÊ\x001boô\x0002@£ËÔ÷)*³S{£6<</p><p>aØÁºe\x0008(×ë´ÓkÔ§ÇÏH\x0015¢Êi#dfÍÁNdXcn\x000f7ÆÐÞ5Å£j\x0018É1PL\x00115¥Íû{\x001cS\x001fMmÏ¢\x0006î&7	¿&°Ã<9æÎÐBô°ìYûê÷ÌÈ\x001fc\x000cnzQÏìÏ«\x0011¼54N÷É«É7Uá¯Ãýéç*ÔÒ\x001d\x001aÝô¯jX|ûêêð¡ÃÚÚ×qZÒ\x0012{ô\x0016IèëÅ?7t3ÔÈ}#¢u:>ñ\x0007\x000cÊ1Ã&ïÞ2\x0019C"CG\x0015äàÑ\.§Wc\x001d\x001cðÊ÷q\x000c\x0013¶gp\x001exó9ï\x000fGP7Ûå\x001c¤jÂ/8t¶<BL¬#G`²{"¹Ù]¢ï\x001cü\x00021õñ\x000bÌqédÃÓ¾j$åG\x001bE]\x001cÑî>Ëe¦î¤è®N*8èl3<Ý÷WÑ\x001fNF9´</p><p>$,!2\x001cÿôIºInvf \x001fÒ³^óÍ	</p><p>:j	®øotôä\x0008LÞüÇ!MäM\x00172«\x001e¾½zùºKçEPóH¦aÿOYB$à\x0000Ë\x00069&4ñÆû¼¿=Ð\x001d\x000e¼Ë¢\x001f¿¤kÊu3åÀ\x000e1z'ú</p><p>Mïs\x001c½\x0010\x0015N§÷öuøv8?þá«YS	\x0007òå¤¦\x0003 IÉÀ\x0011\x001fæuê:¨qXø¼¨_Û®\x0019ùÐ\x000b
G:ÁlÎ­öñ·s\x0019¡¥?¥Ï!W|÷Ðd¤·Á\x0005»\x0013çKÞ£1o}Óiñ-Ñ%z.èû<=Imnßâ\x0016ødÇ~÷Ý_;z÷lñ"\x0017'ªÞJ\x0018Û\x0010\x001dCx\x0019UãLÏ×</p><p>ýáÃ,ÝAì\x0018ì\x0018ø,%2L3¢Q\x0006	ô2¨½ï\|\x000fL=³!ì\x000e;ÔäNÄ</p><p>\x001dûéG´\x001a8O9ê\x0018=\x0005§ü\x0003s°V\x001bé]Û`÷÷yñ0\x0008ü{Ù\x0000áè9\x0017p8QÊ\x0019\x0016SnJG8xá7'o\x000b.8o$îp§Êä\x0015\x001dxöX.*\x0002ÖwqèÐ¶¡¶lÝh9¼¯Bå\x0018\x001e]ÇY\x001eä¾\x000e¥QmÿÂÃð\x0004ÎòO²åôò#£\x0002Ì¡nVð÷}áÒçÓì+\x001f\x00057Ñ3\x0019_Þù\x0014\x001e¦MoQuh\x0003«\x0017\x0013=ío\x0007
¦³$'t QG-ÂÝ#³\x0006íðî?ÒQdÔ²\x001b­(\x000fßkÞÍ0ÏN_»\x0012<xí6]&\x0015}²\x0003\x0016-\x0010\x00188¦ÓN®'p¦\x001c$\x001dðÖÉI=h{füW>¢^m¬CæxÞ7¾÷\x0015\x001bèo§\x001cHöÚ4´V×\x0010>¾I©Ãïðz\x001e¡ü²°8\x001aL\x0002·9K¼\x001b>ÊEûÿêsjà±ÍwoØÚ,ûù"¹Tx{(æ]ðàL9nx9è\x001d#\x001c9Í\x001aÐ\x0019Õ9ÁCz÷þeÛá@\x0004ZHÒ¶×È\x0018î\x000b\x000eÆI\x0003jP\x0016|\x001aJD(êÇã¦½rrÜû§OcçpÀeü\x000cÝ(p"}2À?'º\x001bÍ\x001fýQvucx7\x0013G&7yçy\x001aLÑq¼­Õ¬?Ã\x0004x:q´ÌÓe9\x0002ò\x0002­~=vMôM4:zÉ</p><p>ñ]9u\x0013ÜDyÊðÙ \x001bC\x000cä§g¥\x001c\x000cpwK¼2ô\x0018I\x0003Îï¹6 â88¯¤0¼r¬#mãQä=Æ@0ZO1ùÎ÷ç~ïå»òn£hÝ\x001c?ï«,§Ý\x001aaa[S\x0010û$\x0006'{nD2]ÄSYø8üÖ^\x0015á8^×\x0007¿¡\x000f\å9ö\x0015ºßû\x0002-íTØq\x001añ¦¥¹)t*B°ÍËåØ\x001e\x0010ü\x0015\oc\x0015EÍù~º`Èê(þÔ\x0003Ò.ÃÕ³Ã«}pÄ¥\x0007.N(î\x0010´ø¥\x000c¥\x0005g~\x000f¿D^`é½á§-ã{SB\x00141õ\x0018\x0004¸û{V\x001aÌPIYCÌ\x000e»R~&U\x0012å\x0006ùlQt</p><p>\x0000\x001e#4\x000c$7ô0uÚÃ\x0016R%ctàãb@ÚÑé$\x0012KNëûß;x\x000c=¿ä<Ø¹À\x0000¯f4±z\x000eõ¶öð} ý±
Ûlâ±#2Îo#þp6d»\x0000ß¿f»ÍÄWÖ¡K\x0007j#¿ÕÕQ\x001bÑp:\x0000t!çüòûà¯ãl6°\x0019§0\x001dèt¶R\x0017ÈÈ¶t&P¼x\x001c<\x001eg¿àäö^}ã¥NAyÉÈ{G\x001f´w-\x001dC\x0003nýÛ_\x001b-<¦à#âàÙ\x0001¾H\x001d\x0008.>E±¢F\x001b°Ñ¦\x001b\x0012¼ïyøá7È#j\x001fÎiO0²Ñ²\x000eN­\x0013Õc\x001cüDøwm;Ëw\x000eýÙ¾6\x001eßÓ6­5ï[tÓà\x00159j<xMÏ\x0008Î-':Ñ(^OªB»Ô\x000e\Á\Ö§fÆª=Û\x0008¢#8BªSÈ±y­\x000e×Ï5uê@RoÁåÂ0£èVuq|÷lÇ\x0016\x0008Xù5JB¡%V8é±)û:|B±C\x0013\x0006
É¼ÈD¹£\x00103XGáYåöX"µæ9P.Ì0\x000bMÏÎüÆC\x001a'\x000c§½¦,¥©\x0002\x001c'\x000fVPþôx\x001dV\x0007¢Å¯(JÛ\x0017kÅÑ«ï\x001eCt¬sºÆÁ÷5JJ<í¥³k~-<O4M¡j\i\x001bLJ/:±>s\x001céeí¢6V¾`û½t¸>Í\x000c),ü*(Ã:ÒA±÷ØN\x0005¬uHào[à8üv¿°´\x0017££\x000fö"x\x0008ÅêH­\x001dÅèÏðrõK=p'o6Q¼ÎU»ÖZ¾ÓÁc³ÛöðÊpNÉRgOãô<7ÞHiw;y\x00087x¡U§¿ÖXrdÚëã©'I{K\x0003½Po]ÇCå8\x0002£\x001cüj\x0007Hù\x000e\x000fîfJ'×rI]¹{íÓ\x001bãêèZ¼¶gö³0Lçp
ÙµÑt#8à\x0003z81°ØÀÕ\x00171ÍÃë>¸XÜÿøÑ8­1Þ¾LJaÒhg.âè!åÈ`F\x00171³:§n\x0007\x0019\x001cÈÎúOté,8|¯}aµ-÷#\x0007ú;#k´c\x001c¥	Þ¥cÉ¤Ùè/'?ö\x000f«\x000b³Wè¤#W\x0017/x¢CÛ÷^|nqçDÅØV§\x0019}Îì\x0008\x001c\x001eÍç³åðP°×:dçÊf\x001céø\x0011rk¾]\x0007¾C­UúUu,+\x000c\x0010ä:¥ñ½K¢n
+Ú»ù ¯¾%Q\x0018vUØ9=9Âè\x0006\x001b-ê©æñ±É\x0006t·Vç\x001bð]\x0014f5¯\x0016\x0014¿\x000bÓ
\x0002'R\x000b\x0012êk\x0014\x0011Ó;+XÃ¼8Ptí±ÎÓg\x0002:£ \x0016D\x001b®\x0013ô:æÁ²k\x0004Ó5~\x0011¤ûjrU¥\x0016pXÇ²</p><p> Ýk§Aëx:R\x0008-¢,,£¹\x0017z¥.FFã¬fÆxÖS?éqë¬ËïÐR¾\x001eßáÀ0\x001f¬	ÎPyÎÀ$:»Ks~/<uWÉWÑÀ\]Ú\x000egù¸|-O¢Ô¸und">Ñú\ÛÑÍ¦`8äYZcöõ\x000cu«\x0010\x000cpxm\x000cñ\x001dn\x001f²òÃSz'ËäOåÏ-Ï19·èå\x0004\x0001kôÀI¨FFÃ/\x001fÜµ33ãÓkx·tú®Mô¥¡¡2\x000cáZÃåv¢º\x0001ÏÜÓ	ë\x0004ÐÕò8Zmº¿×t*aÊl'çîy\x0001e</p><p>&t6o{`ÁM°G¿g®bfÊéA&®­\ñÏ¾o-4p*6<1_ ²í¤qà<ø¬ÃiÒ\x001cþG_óäàG'tx\x000cÏ:®À\x0014,¡ùÃ\x0007\x001d\x0004ú¦¬ü1Õ@÷êTçX¢ûk{ãÌÇ«·é nÈFürh¯KââÈMR	N;ºSFy[6xò3hµLÑ§²ôh=²d©'jD:\x0005.|ëpz ·a\x001d\x0000\x0013©®òld0\x001e~\x0016ìCêýû1*t<ü¬3YIÁñÎ¦\x001dÃ4Ì/c\x0006èûë{?uóè©ö}çÄHB¹:Ô8kQ"pM2hÇ¬¦Ü]0\x000cqSæ\x0018ùÀ`ÞßèwvE\x0000%°ÔÓ«(´Û\x001c­v)¨#JPà9ðÀdYïö]¾\x0018^çÄ7Â(oðXcgh¥/eÖyn\x0007\x0002Fqê9<0s\x000bï1*»JÍR*õ9£\x001aIÚZÃ^ÙVyrhceç·¼ÛÈgÿTÖ\x0007\x001fí8×qjÃ±0)ï*ØÒFð\x001d#{iáMi\x000c
_ÃØâJö³Ë¹ªIÍXÜ\x001d·ZYj\x0012ìYô?QI	\x0013	\x001c):
áØ'2º1|Ó©=~2+6´Ë é°íàDJEå\x0006zÄØåPÁ\x001bÎ\x0016©{\x000fØ¢X°»¹G\x0016¤ã\x0007Õ8C:}ü0r@\x000f\ë(¤\x0008Dò§]×ÜC¯5\x001aµ\x001c¯<4Òp?m\x000fY¸OGÔã\x0008Ñ<\x000fMè,
Ó?Ýyþ(k+\x0003\x000fÎ4QÙò©,êÆh$À«ÒÉm÷ÇÍßLÎ"£Óás;ÒÈàîÛð½ÚÜêu@K{ST\x001dºg¨F\x001f=$ëðp\x000c¬toyò)keëÏ'*Ç«æVM\x0012¥\x000c~³¥98ÖÍ±[á`ò\x001b¦>\x001aåè\x0005@\x001cCSá;ØÊÒéò·«\x0000Æ\x0011ëñvt|²ÌÂÏHá4±aü|Ü­_F</p><p>\x001c/Yp¤Û\x0019íÐî¾Ls¯\x0012H¬P\x000cïw¯GHe\x0006>@ éî¿
q»üBÿø|©2ÊÉw½J¥ Ø\x0004zÿAþ\x000füîN\x0013¥2ôi^EÝV
\x000fÇE°\x0013¦>$ÉÌQ'NÑi{ÔÀ%£åPò¯\x0003O{ã#|xµ·>´½5Zà»\x000eSåD%T<i½ \¾\x0005Ç{÷fUA'MD\x0007V\x0019\	\x001b¼kG\x0006F
!eàå§ïÖí¡\x0014ûÊDT:e§XzJù°ËnJîk\x0007Ü½Îtp²ÓANº\x0003\x001eZó^Áýö\x0018\x0005eSw¢·Kt\x0008\x001f¸\x001f"Ã×msõcL;\x001fòÙÅÔi7\x001dôå \x001fÄ±\x001aî75câêÝl\x000f×Ðµ×àêÔhrÛ·4G^\x0019cüî]`\x001fºÍl{ <\x000cÝ¾üêË\x001aáë7ó %/í
`Ã\x0005C¤}Ã?4.­Û	jß\x0001O\x0007\x001d[\x001c_²´(z\x0016'ÐTC'\x0006/egC§\x0015çÀlR\x0016ÿ3G1F/\x0010=\x0011à2#7eck]¶g\x0000§	\x0001</p><p>GU½Mç</p><p>wrE÷ÛÌ%O°«\x0014ÜØnþXyr\x001ck\x000eúÛÙ÷8\x0014«\x001f4 ÊµrÆh¥ó\x0011)÷.m|Ìô÷?& 	>Í\x0019Æ\x0016\x001f$Í¤Ì´'ecQ>]\x0015\x000c\x0008\x000c¦Cú¤à9b©z& WîkCôÐ¹¼ÚëFz«oîIá¹µì6£\x0003êY¡ \x001c©Û¤Iñt6R\x0002$\x001d\x00079</p><p>2<ÆL\x0000B>Ûï{Þ(Tþ\x0007ø"E\x0001üÞBî¯qû¾QÆ\ß\x0005¹u\x001eíÁ§\x0017R6 jÐàm[Âa=\x001bGV%8&¼µ¨`TñT\x000e±\x0004¸u¢Ñ2\x00002Ä\x0005ßÁÕÂyéà¼áèXzÖ©¸6NPÞ*</p><p>\x0017\x001838\x0011h¢\x000eì(·öê0ÿ8\x0015õª\x0007a¼öëtÒî5£\x001b}çX\x001c×±§ö\x0016WÊwíüà»ðÁ2l£\x001d\x0006òÞ_QÞï¥[;ÚãÀ^\x001c9\x0010í2¢[^\x00057"\x00182: u*\x000b\+_ë¬]ß\x0015\x001fÊë\x0010ÞÒ´]\x0003ÊúY	¿Ñ±Q]qIû¢×yØahAó:âVapfm9det\x0008?Ç\x0010:A\x0019=ÓÑ\x001arèvÎfët[`Ïèá×<'\x0013Çëse8ËÆù-¿?\x0007\x0007í?
ì]t\x000e'õV?ñúþ»á\x001b}§oèÐ6Ø\x0018í`rtéXîúD~éÈ\x0003ß!½v;
þàJS"ùL°\x0018îjNr¢Å1üµîóaø>v;õ£¤4ðK\x0000¿êp\x0003ß²/\x0017!Ó§ÏçñmË%\x0003,ò·j~H4ÌFäC;q\x0011¦úëüÐ ú|ûv"[z\x001b\x0014'\x0007çOðîÁc|§§«·hÚ\x0003Nèä;\x00022<2|²\x0010\x0010\x000cÏ»\\x0010®ùè¹ú¾ö]_ÙÚoTJ\x001c\x001c+7zé¬aäPÏï[GºÂm¯\x0010&*¨1\x0005\x0017aÄ­Ñ\x0000Ò\E¹0½9'ax=OV(ý$9\x001fd×\x00085\x000bßgèZ\x000e$</p><p>ê&·1*ËzÌ\x000e2\x0002½Æ\x0018jeG\x0013\x0013E®óX¢æs\x0008ô®kDjÇ±Æé³Î®Ê¢×3|ÏzÊô¦\x000eô^\x000bi\x0017³X0È\x0010íxåþã\x001f#ø=Ð</p><p>_\x001d\x0004GÐWXP68Hy\x0017ü[üµ7xÎ\x0010¤ZÛ(ü\x0013	\x0013ìL,íP\x0014-³\x0013ÓÒ	\x0016\x001a}ÂÁ÷*e>Õwá¹Ï0Ñ3¸\x001a®MgDvÛ(\x000eØÊÂ\x0003¬\x001acà¬£wMy<Ý6\x0017:Ìåg;£`xÒçýÛt¦Gßªàùnv}R>\x000cvø^M\x001bÝç:\x000füÐ.EÔu</p><p>\x0018'´\x0013\x0004£Î>wôÇ\x0008h&oÐsDòKrNe868û^ÙÇ1áa¿üYoò+\x000fYD<1¹ÒÔÉ\x0004\x000cýá,{R¯CõØùv¢¶à¿2g\x0003èô\x001b>`Ñ\x0019ÇãÅ;\x000c¯Ó #ùêÈ6ºL÷f\x0002Ê</p><p>©Ï\x0019W6q&\x001d1\x001eùùä4Ê\x0003¼\x000bÎrðÒ'£À{!.Yw6ÃÉz_|%O\x0007¹Á½ÁU×{^fý#ÌÊ·GÎKº\x001cë]\x0012¹ï°ÝµÕe:¥ß«KøâX=t\x001fºH0\x001e<ø`þ¼Þ»L¡§:uìvÐÝù­vPF;øìà>ÕAË­Nçfökh\x0010\x0019¡Ì\x0010\x0004\x0000¿W°¾;\x0000'XFå \x0004×(¨ìí=C\x0002MþÚkc²I0üvîì×0J­é5\x000c\x0003&áO	ä,Ó</p><p>2ÓI\x0015\x000c3«:½¾¨dumÌÒB©´Ý¡&æc¸µo\x0014;°)\x0011¦×¹'æ4\x001bÎ)î.9]V»\x0014$'úg¨2Cjõµ\x0001ïN¥èj$ê«[åR\x0000z
Ø</p><p>nðn\x0012=8îdGedX\x0005Ù\x001c\x000bo\x0015Ï§¶ñ\x0013Ý{*»2U\x000cáiX\x0003wp@¬²$\x000c®Ø\x001eË_÷¶\x000e·¿u¬c\x001c¤\x001fç>\x00131:\x000e3íÉ·yO\x001fk¥úÝ\x000e&ÆØÝ²RNôµ:¶W,\x000eËwø\x0010Çóìîó8:ã\x0008ì\x0019\x0007KLë£Hp:\x0004ËäNgrpû¢+åÇmëE÷Æ¨v8¯{\x000fÌ®ÆH»&\x001e%×æ\x0011[\x001b sVóÏÛð ÃÛè\x000cø	4Ó\x0003ôlG´N\x0013ÿÉªÌ±GN{lcêHcq¤6\x0010©s{\x0018:¼°28×±ÔîÀ¹t"èuà\x0013þÝ\x0015ã&KÕqísRt%\x0011\'{!£ñ\x0019£Ê)ÏMèÜE¼Í}fx-0@'úÞ½SfÒ\x001e\x0005\x001eÄfuÃÈ\x001f¢yeÁÓF}\x0007\x0002Îá{Ïündï»4\x0013ý\x0000\x0014Y?ÈË:¿ûuÒMQæ·`l\x0002\x0015|ENÎìË
]Wgæû§ñºÑ\çáÇå¤ëD\x001bË57\x0011²È\x0003ètmË«»°ÖcäofA§wúg\x0001w\x001c¢¼ßXë(÷(ë(¬Þ\x0010a\x000eJ$)¯¾¨\x000fÂÚhï6:	\x0014æºN\x0001|ÂM/>ü\x001eF/¡\x0005JÁÚøÔU#y³¥ÓÃsÀG[øâÔó*7kÑ\x0006\x000fÃ\x0001\x001d@ñª¢\x0007>ê\x0010\x0001g\x000ct^¯â÷\x001aä:\x001e<{¥\x001f³(}Tp¸n\x0002¿©\x0010\x0005vSKÜIRwî«íìüÞ³u\x0003\x000b\x000eK\x001b	v\x0000ô\x001aÞã\x0014ÃÌ¥\\x000eV\x0004¨.z(ÛêÇ\x000eCÑ\x000b®÷\x0019ÙûÓ\x0001ÞêÎÒàS.JgðKr?åÉXYFõã4&úÐyq¢ð'?u÷Dë"E\x0006îùsrêð¬é\x001fòÙrx#T\x000e:K¹Í\x0019:¢\x0015-èt S\x001bK÷F®­\x001cCùO¸w\x0012\x0018Q5¸ÙSÔmÊ´ó:úÇøc´&÷Y½vÏuðñp\x001câØ</p><p>Ü¼äs°3¬=m´Ï</p><p>ã<\x0010«=â\x0003Y\x0007]Czé,¶-mWoÒ¾vï$íkÒ4@Ë\x000bío}¶ç¥ä¿Þ6»²¿½ñ\x0012K`D}6óêÕØ-=s­\x000bùÉ7ü¢ëâÓÆt\x0008\x001d~£³ÿ]{_'¢ëiÄ¿>\x001dX\x001d\x0011ÛP½@ä@Èr+N|+Oúr:=i
Ê\x001cÕ»ú[\x0017v«Û}²©</p><p>\x0019\x0000ò&"Æîk\x0008¹6À5\x0008Ä¯	\x0008C7?8\x001b\x0018#ÚEµÞQ^ÆDà^[\x00006Fë0Æo\x0004µ}H#áíæì@åÙã8ÕÔAFg\x0008r©;K8à´yØq\x0014s}\x00041¨3Ð¦hZîm\x0014\x0019î7\x0014¥]ÈlèF§ÓdÒöÒUq
SCòý)¥¦ôáÇæYôò®Uy\x0003»6yaõ·Îæ<\x0019%W6|\x001dü\x0008nð8CõÐNIÐÇa@b\x0015Ùç:8¹9Ê</p><p>5Æ÷\x001aSÓ/Q^ÎÒ§^vä;³½Xí9gõÖ((ÓµÕ\x00058n'ËAéLÜÓÉ4§ÜNj\x000cHNÎð¡á¥M±áG'ÔTËL´­·©\x001då'Ún\x0018\x0019Ìî¡EÔ\x0013\x001ey^½y»ðÐ\x0016;\x0005É¥úÑÈòj
Øõå'>Öé\x000eVyí+ßeC¡>&ÑZ£íÜgêËQvÙVªº\x0013\x0000p¶\x0017'«®{hÔ¾cìc:NqW\x0012Ð#pðtþôYd?Ëå6ê*ÒÁ\x0006×!©q¤:@Ç:Vzì]VËg×»%G\x001f¾ÈwkÊÇMÄ¬ìÊÆH\x000fKú\x0003~®ý»¾c¯\x0007ï\x0002\x000fÞëp¯a]ëÝÂf_Èªò.ú´¶êºKÞè0\x0013}\x001cêÌA mèJî6ûeÈ\x001ay.m+~\x0017nms¯5"Åª-</p><p>áXA^Wt}\x0005Ý:Aø\x0008\x000e5ìâ|ÏdÂ1\x0018n{ú\x0008\x00029ä0
I0NoËñ\x001d4#h\x0002ËüîÕØ,ub\x0010\x0011"\x001cor'</p><p>àÁ\x0008#äYS9Ã%Ü\x001c\x0007;¸.<=Õ£G³q\x0005\x0014£+\x001cKÓÒ¨>å­cH\x001b\x000euæ©qB¢Öâ\x0011g¸÷ýîcùì;±\x000cÑ3´j^6×VIÁB»¡g¬_¿Þ\x0010.</p><p>f</p><p>ÕÙûð°ëú\x000cá&¿vKåu:\x0008è0âu\x000c`¸>ÎjåÇ¹?></p>
  
### Reference
* http://blogs.wsj.com/cio/2013/10/08/adobe-source-code-leak-is-bad-news-for-u-s-government/

  
#### CWE Id : 540
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### X-Frame-Options Header Not Set
##### Medium (Medium)
  
  
  
  
#### Description
<p>X-Frame-Options header is not included in the HTTP response to protect against 'ClickJacking' attacks.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/creation-de-podcast-1248797336/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/creation-de-podcast-1248797336/voir)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/contact/creer](https://lemarche.inclusion.beta.gouv.fr/fr/contact/creer)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/inscription](https://lemarche.inclusion.beta.gouv.fr/fr/inscription)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/page/cest-quoi-linclusion](https://lemarche.inclusion.beta.gouv.fr/fr/page/cest-quoi-linclusion)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/page/faq](https://lemarche.inclusion.beta.gouv.fr/fr/page/faq)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/page/qui-sommes-nous](https://lemarche.inclusion.beta.gouv.fr/fr/page/qui-sommes-nous)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/identification](https://lemarche.inclusion.beta.gouv.fr/fr/identification)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/favorite](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/favorite)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/test-recette-applicative-informatique-882556899/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/test-recette-applicative-informatique-882556899/voir)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/page/mentions-legales](https://lemarche.inclusion.beta.gouv.fr/fr/page/mentions-legales)
  
  
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
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/deplacement-de-mobilier-avant-apres-travaux-1583804190/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/deplacement-de-mobilier-avant-apres-travaux-1583804190/voir)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form method="post" action="/fr/quote/1583804190/flash" id="quote-form" class="date-selection">`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/contact/creer](https://lemarche.inclusion.beta.gouv.fr/fr/contact/creer)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form method="post" action="/fr/contact/creer">`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/inscription](https://lemarche.inclusion.beta.gouv.fr/fr/inscription)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form class="form-signup" action="/fr/inscription" method="POST" autocomplete="off">`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/prestation-de-service-905761325/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/prestation-de-service-905761325/voir)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form method="post" action="/fr/quote/905761325/flash" id="quote-form" class="date-selection">`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/creation-de-podcast-1248797336/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/creation-de-podcast-1248797336/voir)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form method="post" action="/fr/quote/1248797336/flash" id="quote-form" class="date-selection">`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/favorite](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/favorite)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form method="get" action="/fr/annonce/resultat-recherche" class="form-category alt col-xs-12">`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/identification](https://lemarche.inclusion.beta.gouv.fr/fr/identification)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form class="form-signup" action="/fr/identification-verification"
                          method="POST">`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/collecte-et-valorisation-de-vos-dechets-908837917/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/collecte-et-valorisation-de-vos-dechets-908837917/voir)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form method="post" action="/fr/quote/908837917/flash" id="quote-form" class="date-selection">`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/cleaning-day-1367194631/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/cleaning-day-1367194631/voir)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form method="post" action="/fr/quote/1367194631/flash" id="quote-form" class="date-selection">`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/insertion-solidairte-innovations-sociales-342395622/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/insertion-solidairte-innovations-sociales-342395622/voir)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form method="post" action="/fr/quote/342395622/flash" id="quote-form" class="date-selection">`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/demenagement-802691713/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/demenagement-802691713/voir)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form method="post" action="/fr/quote/802691713/flash" id="quote-form" class="date-selection">`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/test-recette-applicative-informatique-882556899/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/test-recette-applicative-informatique-882556899/voir)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form method="post" action="/fr/quote/882556899/flash" id="quote-form" class="date-selection">`
  
  
  
  
Instances: 12
  
### Solution
<p>Phase: Architecture and Design</p><p>Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.</p><p>For example, use anti-CSRF packages such as the OWASP CSRFGuard.</p><p></p><p>Phase: Implementation</p><p>Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script.</p><p></p><p>Phase: Architecture and Design</p><p>Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).</p><p>Note that this can be bypassed using XSS.</p><p></p><p>Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.</p><p>Note that this can be bypassed using XSS.</p><p></p><p>Use the ESAPI Session Management control.</p><p>This control includes a component for CSRF.</p><p></p><p>Do not use the GET method for any request that triggers a state change.</p><p></p><p>Phase: Implementation</p><p>Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.</p>
  
### Other information
<p>No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF] was found in the following HTML form: [Form 1: ].</p>
  
### Reference
* http://projects.webappsec.org/Cross-Site-Request-Forgery
* http://cwe.mitre.org/data/definitions/352.html

  
#### CWE Id : 352
  
#### WASC Id : 9
  
#### Source ID : 3

  
  
  
  
### Application Error Disclosure
##### Low (Medium)
  
  
  
  
#### Description
<p>This page contains an error/warning message that may disclose sensitive information like the location of the file that produced the unhandled exception. This information can be used to launch further attacks against the web application. The alert could be a false positive if the error message is found inside a documentation page.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/media/cache/resolve/listing_medium/uploads/listings/images/](https://lemarche.inclusion.beta.gouv.fr/fr/media/cache/resolve/listing_medium/uploads/listings/images/)
  
  
  * Method: `GET`
  
  
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification](https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification)
  
  
  * Method: `GET`
  
  
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  
  
  
  
Instances: 2
  
### Solution
<p>Review the source code of this page. Implement custom error pages. Consider implementing a mechanism to provide a unique error reference/identifier to the client (browser) while logging the details on the server side and not exposing them to the user.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Big Redirect Detected (Potential Sensitive Information Leak)
##### Low (Medium)
  
  
  
  
#### Description
<p>The server has responded with a redirect that seems to provide a large response. This may indicate that although the server sent a redirect it also responded with body content (which may include sensitive details, PII, etc.).</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/quote/802691713/new?budget&communication&prestaStartDate](https://lemarche.inclusion.beta.gouv.fr/fr/quote/802691713/new?budget&communication&prestaStartDate)
  
  
  * Method: `POST`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/repertoire/siae](https://lemarche.inclusion.beta.gouv.fr/fr/repertoire/siae)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/quote/342395622/new?budget&communication&prestaStartDate](https://lemarche.inclusion.beta.gouv.fr/fr/quote/342395622/new?budget&communication&prestaStartDate)
  
  
  * Method: `POST`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification](https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification)
  
  
  * Method: `POST`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/mot-de-passe-reinitialisation-envoi-email](https://lemarche.inclusion.beta.gouv.fr/fr/mot-de-passe-reinitialisation-envoi-email)
  
  
  * Method: `POST`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr](https://lemarche.inclusion.beta.gouv.fr/fr)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/quote/908837917/new?budget&communication&prestaStartDate](https://lemarche.inclusion.beta.gouv.fr/fr/quote/908837917/new?budget&communication&prestaStartDate)
  
  
  * Method: `POST`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/quote/905761325/new?budget&communication&prestaStartDate](https://lemarche.inclusion.beta.gouv.fr/fr/quote/905761325/new?budget&communication&prestaStartDate)
  
  
  * Method: `POST`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/quote/1248797336/new?budget&communication&prestaStartDate](https://lemarche.inclusion.beta.gouv.fr/fr/quote/1248797336/new?budget&communication&prestaStartDate)
  
  
  * Method: `POST`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/quote/1367194631/new?budget&communication&prestaStartDate](https://lemarche.inclusion.beta.gouv.fr/fr/quote/1367194631/new?budget&communication&prestaStartDate)
  
  
  * Method: `POST`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/quote/1583804190/new?budget&communication&prestaStartDate](https://lemarche.inclusion.beta.gouv.fr/fr/quote/1583804190/new?budget&communication&prestaStartDate)
  
  
  * Method: `POST`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/quote/882556899/new?budget&communication&prestaStartDate](https://lemarche.inclusion.beta.gouv.fr/fr/quote/882556899/new?budget&communication&prestaStartDate)
  
  
  * Method: `POST`
  
  
  
  
Instances: 12
  
### Solution
<p>Ensure that no sensitive information is leaked via redirect responses. Redirect responses should have almost no content.</p>
  
### Other information
<p>Location header URI length: 57 [https://lemarche.inclusion.beta.gouv.fr/fr/identification].</p><p>Predicted response size: 357.</p><p>Response Body Length: 474.</p>
  
### Reference
* 

  
#### CWE Id : 201
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Cookie No HttpOnly Flag
##### Low (Medium)
  
  
  
  
#### Description
<p>A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript. If a malicious script can be run on this page then the cookie will be accessible and can be transmitted to another site. If this is a session cookie then session hijacking may be possible.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/](https://lemarche.inclusion.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `hl`
  
  
  * Evidence: `Set-Cookie: hl`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr](https://lemarche.inclusion.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Parameter: `hl`
  
  
  * Evidence: `Set-Cookie: hl`
  
  
  
  
Instances: 2
  
### Solution
<p>Ensure that the HttpOnly flag is set for all cookies.</p>
  
### Reference
* https://owasp.org/www-community/HttpOnly

  
#### CWE Id : 16
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Cookie Without SameSite Attribute
##### Low (Medium)
  
  
  
  
#### Description
<p>A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is an effective counter measure to cross-site request forgery, cross-site script inclusion, and timing attacks.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `_csess`
  
  
  * Evidence: `Set-Cookie: _csess`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/](https://lemarche.inclusion.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `hl`
  
  
  * Evidence: `Set-Cookie: hl`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr](https://lemarche.inclusion.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Parameter: `hl`
  
  
  * Evidence: `Set-Cookie: hl`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr](https://lemarche.inclusion.beta.gouv.fr/fr)
  
  
  * Method: `GET`
  
  
  * Parameter: `_csess`
  
  
  * Evidence: `Set-Cookie: _csess`
  
  
  
  
Instances: 4
  
### Solution
<p>Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.</p>
  
### Reference
* https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site

  
#### CWE Id : 16
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Cookie Without Secure Flag
##### Low (Medium)
  
  
  
  
#### Description
<p>A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr](https://lemarche.inclusion.beta.gouv.fr/fr)
  
  
  * Method: `GET`
  
  
  * Parameter: `_csess`
  
  
  * Evidence: `Set-Cookie: _csess`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/](https://lemarche.inclusion.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `hl`
  
  
  * Evidence: `Set-Cookie: hl`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `_csess`
  
  
  * Evidence: `Set-Cookie: _csess`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr](https://lemarche.inclusion.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Parameter: `hl`
  
  
  * Evidence: `Set-Cookie: hl`
  
  
  
  
Instances: 4
  
### Solution
<p>Whenever a cookie contains sensitive information or is a session token, then it should always be passed using an encrypted channel. Ensure that the secure flag is set for cookies containing such sensitive information.</p>
  
### Reference
* https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html

  
#### CWE Id : 614
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Cross-Domain JavaScript Source File Inclusion
##### Low (Medium)
  
  
  
  
#### Description
<p>The page includes one or more script files from a third-party domain.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/favorite](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/favorite)
  
  
  * Method: `GET`
  
  
  * Parameter: `//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ`
  
  
  * Evidence: `<script type="text/javascript"
        src="//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ">
</script>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/insertion-solidairte-innovations-sociales-342395622/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/insertion-solidairte-innovations-sociales-342395622/voir)
  
  
  * Method: `GET`
  
  
  * Parameter: `//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ`
  
  
  * Evidence: `<script type="text/javascript"
        src="//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ">
</script>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/creation-de-podcast-1248797336/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/creation-de-podcast-1248797336/voir)
  
  
  * Method: `GET`
  
  
  * Parameter: `//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ`
  
  
  * Evidence: `<script type="text/javascript"
        src="//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ">
</script>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/deplacement-de-mobilier-avant-apres-travaux-1583804190/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/deplacement-de-mobilier-avant-apres-travaux-1583804190/voir)
  
  
  * Method: `GET`
  
  
  * Parameter: `//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ`
  
  
  * Evidence: `<script type="text/javascript"
        src="//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ">
</script>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/communication-598263982/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/communication-598263982/voir)
  
  
  * Method: `GET`
  
  
  * Parameter: `//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ`
  
  
  * Evidence: `<script type="text/javascript"
        src="//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ">
</script>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/prestation-de-service-905761325/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/prestation-de-service-905761325/voir)
  
  
  * Method: `GET`
  
  
  * Parameter: `//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ`
  
  
  * Evidence: `<script type="text/javascript"
        src="//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ">
</script>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/test-recette-applicative-informatique-882556899/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/test-recette-applicative-informatique-882556899/voir)
  
  
  * Method: `GET`
  
  
  * Parameter: `//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ`
  
  
  * Evidence: `<script type="text/javascript"
        src="//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ">
</script>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/collecte-et-valorisation-de-vos-dechets-908837917/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/collecte-et-valorisation-de-vos-dechets-908837917/voir)
  
  
  * Method: `GET`
  
  
  * Parameter: `//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ`
  
  
  * Evidence: `<script type="text/javascript"
        src="//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ">
</script>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/demenagement-802691713/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/demenagement-802691713/voir)
  
  
  * Method: `GET`
  
  
  * Parameter: `//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ`
  
  
  * Evidence: `<script type="text/javascript"
        src="//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ">
</script>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/cleaning-day-1367194631/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/cleaning-day-1367194631/voir)
  
  
  * Method: `GET`
  
  
  * Parameter: `//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ`
  
  
  * Evidence: `<script type="text/javascript"
        src="//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ">
</script>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ`
  
  
  * Evidence: `<script type="text/javascript"
        src="//maps.googleapis.com/maps/api/js?libraries=places&language=fr&key=AIzaSyA_WKj-U7bkD3UEadmabO_jEa8V5k1IUjQ">
</script>`
  
  
  
  
Instances: 11
  
### Solution
<p>Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.</p>
  
### Reference
* 

  
#### CWE Id : 829
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Dangerous JS Functions
##### Low (Low)
  
  
  
  
#### Description
<p>A dangerous JS function seems to be in use that would leave the site vulnerable.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/logistique-e-commerce-btoc-et-btob-1344825001/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/logistique-e-commerce-btoc-et-btob-1344825001/voir)
  
  
  * Method: `GET`
  
  
  * Evidence: `eval`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/assets/0.cd5673da.js](https://lemarche.inclusion.beta.gouv.fr/assets/0.cd5673da.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `Eval`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/test-recette-applicative-informatique-882556899/voir](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/test-recette-applicative-informatique-882556899/voir)
  
  
  * Method: `GET`
  
  
  * Evidence: `eval`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/assets/common.a58648b7.js](https://lemarche.inclusion.beta.gouv.fr/assets/common.a58648b7.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `eVal`
  
  
  
  
Instances: 4
  
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
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification](https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/login-check](https://lemarche.inclusion.beta.gouv.fr/en/login-check)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer](https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix](https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/sitemap.xml](https://lemarche.inclusion.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/currency/*/switch](https://lemarche.inclusion.beta.gouv.fr/en/currency/*/switch)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/login-check](https://lemarche.inclusion.beta.gouv.fr/fr/login-check)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price](https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/listing-availabilities/*/*/](https://lemarche.inclusion.beta.gouv.fr/en/listing-availabilities/*/*/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce-disponibilitee/*/*/](https://lemarche.inclusion.beta.gouv.fr/fr/annonce-disponibilitee/*/*/)
  
  
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
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/contact/creer](https://lemarche.inclusion.beta.gouv.fr/fr/contact/creer)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=0, must-revalidate, private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/robots.txt](https://lemarche.inclusion.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/inscription](https://lemarche.inclusion.beta.gouv.fr/fr/inscription)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=0, must-revalidate, private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/identification](https://lemarche.inclusion.beta.gouv.fr/fr/identification)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=0, must-revalidate, private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/css/ie.css](https://lemarche.inclusion.beta.gouv.fr/css/ie.css)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=86400`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/page/qui-sommes-nous](https://lemarche.inclusion.beta.gouv.fr/fr/page/qui-sommes-nous)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=0, must-revalidate, private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=0, must-revalidate, private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/page/faq](https://lemarche.inclusion.beta.gouv.fr/fr/page/faq)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=0, must-revalidate, private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/page/mentions-legales](https://lemarche.inclusion.beta.gouv.fr/fr/page/mentions-legales)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=0, must-revalidate, private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/favorite](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/favorite)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=0, must-revalidate, private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/page/cest-quoi-linclusion](https://lemarche.inclusion.beta.gouv.fr/fr/page/cest-quoi-linclusion)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=0, must-revalidate, private`
  
  
  
  
Instances: 11
  
### Solution
<p>Whenever possible ensure the cache-control HTTP header is set with no-cache, no-store, must-revalidate; and that the pragma HTTP header is set with no-cache.</p>
  
### Reference
* https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching

  
#### CWE Id : 525
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Debug Error Messages
##### Low (Medium)
  
  
  
  
#### Description
<p>The response appeared to contain common error messages returned by platforms such as ASP.NET, and Web-servers such as IIS and Apache. You can configure the list of common debug messages.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification](https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification)
  
  
  * Method: `GET`
  
  
  * Evidence: `Internal Server Error`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/media/cache/resolve/listing_medium/uploads/listings/images/](https://lemarche.inclusion.beta.gouv.fr/fr/media/cache/resolve/listing_medium/uploads/listings/images/)
  
  
  * Method: `GET`
  
  
  * Evidence: `Internal Server Error`
  
  
  
  
Instances: 2
  
### Solution
<p>Disable debugging messages before pushing to production.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Strict-Transport-Security Header Not Set
##### Low (High)
  
  
  
  
#### Description
<p>HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying user agents (such as a web browser) are to interact with it using only secure HTTPS connections (i.e. HTTP layered over TLS/SSL). HSTS is an IETF standards track protocol and is specified in RFC 6797.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer](https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/currency/*/switch](https://lemarche.inclusion.beta.gouv.fr/en/currency/*/switch)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/listing-availabilities/*/*/](https://lemarche.inclusion.beta.gouv.fr/en/listing-availabilities/*/*/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification](https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/login-check](https://lemarche.inclusion.beta.gouv.fr/fr/login-check)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce-disponibilitee/*/*/](https://lemarche.inclusion.beta.gouv.fr/fr/annonce-disponibilitee/*/*/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix](https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/sitemap.xml](https://lemarche.inclusion.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/robots.txt](https://lemarche.inclusion.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price](https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price)
  
  
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
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/page/mentions-legales](https://lemarche.inclusion.beta.gouv.fr/fr/page/mentions-legales)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/robots.txt](https://lemarche.inclusion.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/page/faq](https://lemarche.inclusion.beta.gouv.fr/fr/page/faq)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/page/qui-sommes-nous](https://lemarche.inclusion.beta.gouv.fr/fr/page/qui-sommes-nous)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/css/ie.css](https://lemarche.inclusion.beta.gouv.fr/css/ie.css)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/identification](https://lemarche.inclusion.beta.gouv.fr/fr/identification)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/inscription](https://lemarche.inclusion.beta.gouv.fr/fr/inscription)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/page/cest-quoi-linclusion](https://lemarche.inclusion.beta.gouv.fr/fr/page/cest-quoi-linclusion)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/favorite](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/favorite)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/contact/creer](https://lemarche.inclusion.beta.gouv.fr/fr/contact/creer)
  
  
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
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/sitemap.xml](https://lemarche.inclusion.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `user_registration_personType_1`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix](https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix)
  
  
  * Method: `GET`
  
  
  * Evidence: `user_registration_personType_1`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `user_registration_personType_1`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price](https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price)
  
  
  * Method: `GET`
  
  
  * Evidence: `user_registration_personType_1`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/login-check](https://lemarche.inclusion.beta.gouv.fr/en/login-check)
  
  
  * Method: `GET`
  
  
  * Evidence: `user_registration_personType_1`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification](https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification)
  
  
  * Method: `GET`
  
  
  * Evidence: `user_registration_personType_1`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer](https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer)
  
  
  * Method: `GET`
  
  
  * Evidence: `user_registration_personType_1`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/currency/*/switch](https://lemarche.inclusion.beta.gouv.fr/en/currency/*/switch)
  
  
  * Method: `GET`
  
  
  * Evidence: `user_registration_personType_1`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/login-check](https://lemarche.inclusion.beta.gouv.fr/fr/login-check)
  
  
  * Method: `GET`
  
  
  * Evidence: `user_registration_personType_1`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce-disponibilitee/*/*/](https://lemarche.inclusion.beta.gouv.fr/fr/annonce-disponibilitee/*/*/)
  
  
  * Method: `GET`
  
  
  * Evidence: `user_registration_personType_1`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/listing-availabilities/*/*/](https://lemarche.inclusion.beta.gouv.fr/en/listing-availabilities/*/*/)
  
  
  * Method: `GET`
  
  
  * Evidence: `user_registration_personType_1`
  
  
  
  
Instances: 11
  
### Solution
<p>Manually confirm that the Base64 data does not leak sensitive information, and that the data cannot be aggregated/used to exploit other vulnerabilities.</p>
  
### Other information
<p>�ǫ�����kjب��^��'O*^�</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Sensitive Information in URL
##### Informational (Medium)
  
  
  
  
#### Description
<p>The request appeared to contain sensitive information leaked in the URL. This can violate PCI and most organizational compliance policies. You can configure the list of strings for this check to add or remove values specific to your environment.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/mot-de-passe-reinitialisation-verification-email?username=ZAP](https://lemarche.inclusion.beta.gouv.fr/fr/mot-de-passe-reinitialisation-verification-email?username=ZAP)
  
  
  * Method: `GET`
  
  
  * Parameter: `username`
  
  
  * Evidence: `username`
  
  
  
  
Instances: 1
  
### Solution
<p>Do not pass sensitive information in URIs.</p>
  
### Other information
<p>The URL contains potentially sensitive information. The following string was found via the pattern: user</p><p>username</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Suspicious Comments
##### Informational (Medium)
  
  
  
  
#### Description
<p>The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price](https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer](https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/sitemap.xml](https://lemarche.inclusion.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix](https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
Instances: 5
  
### Solution
<p>Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.</p>
  
### Other information
<p>The following pattern was used: \bUSER\b and was detected 2 times, the first in the element starting with: "<!-- allow a user to go to the main content of the page -->", see evidence field for the suspicious comment/snippet.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Suspicious Comments
##### Informational (Low)
  
  
  
  
#### Description
<p>The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer](https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer)
  
  
  * Method: `GET`
  
  
  * Evidence: `query`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `query`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix](https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix)
  
  
  * Method: `GET`
  
  
  * Evidence: `query`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price](https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price)
  
  
  * Method: `GET`
  
  
  * Evidence: `query`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `todo`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/sitemap.xml](https://lemarche.inclusion.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `query`
  
  
  
  
Instances: 6
  
### Solution
<p>Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.</p>
  
### Other information
<p>The following pattern was used: \bQUERY\b and was detected in the element starting with: "<script></p><p>var ORDER = 1;</p><p>var SESSION_ID = "";</p><p>var VERSION = 1;</p><p></p><p>//export function track(page, action, meta={}) {</p><p>async function t", see evidence field for the suspicious comment/snippet.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Modern Web Application
##### Informational (Medium)
  
  
  
  
#### Description
<p>The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification](https://lemarche.inclusion.beta.gouv.fr/fr/identification-verification)
  
  
  * Method: `GET`
  
  
  * Evidence: `<noscript>Javascript must be enabled for the correct page display</noscript>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix](https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix)
  
  
  * Method: `GET`
  
  
  * Evidence: `<noscript>Javascript must be enabled for the correct page display</noscript>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/currency/*/switch](https://lemarche.inclusion.beta.gouv.fr/en/currency/*/switch)
  
  
  * Method: `GET`
  
  
  * Evidence: `<noscript>Javascript must be enabled for the correct page display</noscript>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer](https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer)
  
  
  * Method: `GET`
  
  
  * Evidence: `<noscript>Javascript must be enabled for the correct page display</noscript>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price](https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price)
  
  
  * Method: `GET`
  
  
  * Evidence: `<noscript>Javascript must be enabled for the correct page display</noscript>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="#" class="slider-prev">Previous Slide</a>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce-disponibilitee/*/*/](https://lemarche.inclusion.beta.gouv.fr/fr/annonce-disponibilitee/*/*/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<noscript>Javascript must be enabled for the correct page display</noscript>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/sitemap.xml](https://lemarche.inclusion.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `<noscript>Javascript must be enabled for the correct page display</noscript>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/login-check](https://lemarche.inclusion.beta.gouv.fr/fr/login-check)
  
  
  * Method: `GET`
  
  
  * Evidence: `<noscript>Javascript must be enabled for the correct page display</noscript>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/listing-availabilities/*/*/](https://lemarche.inclusion.beta.gouv.fr/en/listing-availabilities/*/*/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<noscript>Javascript must be enabled for the correct page display</noscript>`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/login-check](https://lemarche.inclusion.beta.gouv.fr/en/login-check)
  
  
  * Method: `GET`
  
  
  * Evidence: `<noscript>Javascript must be enabled for the correct page display</noscript>`
  
  
  
  
Instances: 11
  
### Solution
<p>This is an informational alert and so no changes are required.</p>
  
### Other information
<p>A noScript tag has been found, which is an indication that the application works differently with JavaScript enabled compared to when it is not.</p>
  
### Reference
* 

  
#### Source ID : 3

  
  
  
  
### Non-Storable Content
##### Informational (Medium)
  
  
  
  
#### Description
<p>The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr](https://lemarche.inclusion.beta.gouv.fr/fr)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/currency/*/switch](https://lemarche.inclusion.beta.gouv.fr/en/currency/*/switch)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price](https://lemarche.inclusion.beta.gouv.fr/en/booking/*/price)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer](https://lemarche.inclusion.beta.gouv.fr/fr/devise/*/changer)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix](https://lemarche.inclusion.beta.gouv.fr/fr/reservation/*/prix)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/sitemap.xml](https://lemarche.inclusion.beta.gouv.fr/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/](https://lemarche.inclusion.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr](https://lemarche.inclusion.beta.gouv.fr)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
Instances: 9
  
### Solution
<p>The content may be marked as storable by ensuring that the following conditions are satisfied:</p><p>The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)</p><p>The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)</p><p>The "no-store" cache directive must not appear in the request or response header fields</p><p>For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response</p><p>For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)</p><p>In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:</p><p>It must contain an "Expires" header field</p><p>It must contain a "max-age" response directive</p><p>For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive</p><p>It must contain a "Cache Control Extension" that allows it to be cached</p><p>It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).   </p>
  
### Reference
* https://tools.ietf.org/html/rfc7234
* https://tools.ietf.org/html/rfc7231
* http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234)

  
#### CWE Id : 524
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Storable and Cacheable Content
##### Informational (Medium)
  
  
  
  
#### Description
<p>The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users.  If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/robots.txt](https://lemarche.inclusion.beta.gouv.fr/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
Instances: 1
  
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
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `196196765`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `620319126`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `827996880`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `271298990`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `451245589`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `1686205550`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `700243201`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `1921461073`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `1387684049`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/](https://lemarche.inclusion.beta.gouv.fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `31536000`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `996671098`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `1421471336`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `1217409481`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `1314884699`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `2009717386`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `423363571`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `1369253962`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `607096780`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `730668561`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/](https://lemarche.inclusion.beta.gouv.fr/fr/)
  
  
  * Method: `GET`
  
  
  * Evidence: `1248797336`
  
  
  
  
Instances: 43
  
### Solution
<p>Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.</p>
  
### Other information
<p>196196765, which evaluates to: 1976-03-20 19:06:05</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### User Controllable HTML Element Attribute (Potential XSS)
##### Informational (Low)
  
  
  
  
#### Description
<p>This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.</p>
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `time_range[nb_minutes]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `time_range[nb_minutes]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `date_range[start]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
* URL: [https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52](https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52)
  
  
  * Method: `GET`
  
  
  * Parameter: `characteristics[5]`
  
  
  
  
Instances: 27
  
### Solution
<p>Validate all input and sanitize output it before writing to any HTML attributes.</p>
  
### Other information
<p>User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:</p><p></p><p>https://lemarche.inclusion.beta.gouv.fr/fr/annonce/resultat-recherche?characteristics%5B2%5D=3&characteristics%5B5%5D=12&date_range%5Bend%5D&date_range%5Bnb_days%5D=1&date_range%5Bstart%5D=ZAP&listing_categories%5BlistingListingCategories%5D%5B%5D=2&location%5Baddress%5D&location%5BaddressType%5D&location%5Barea%5D&location%5Bcity%5D&location%5Bcountry%5D&location%5Bdepartment%5D&location%5Blat%5D&location%5Blng%5D&location%5Broute%5D&location%5BstreetNumber%5D&location%5Bviewport%5D&location%5Bzip%5D&page=1&sort_by=recommended&time_range%5Bend%5D%5Bhour%5D=0&time_range%5Bend%5D%5Bminute%5D=0&time_range%5Bnb_minutes%5D=60&time_range%5Bstart%5D%5Bhour%5D=0&time_range%5Bstart%5D%5Bminute%5D=0&time_range%5Bstart_picker%5D=15%3A48%3A52</p><p></p><p>appears to include user input in: </p><p></p><p>a(n) [input] tag [value] attribute </p><p></p><p>The user input found was:</p><p>characteristics[5]=12</p><p></p><p>The user-controlled value was:</p><p>129</p>
  
### Reference
* http://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-html-attribute

  
#### CWE Id : 20
  
#### WASC Id : 20
  
#### Source ID : 3
