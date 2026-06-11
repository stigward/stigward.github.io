---
title: "A Silly Satellite Wi-Fi Router Bug - Redport Pre-Auth RCE"
date: 2025-07-24
description: "Pre-auth RCE over LAN in the RedPort wXa-223 satellite Wi-Fi router, found within minutes of unpacking the firmware."
tags: [embedded, research, rce]
---

# Overview: 
A few months ago, I was browsing the strange world of satellite products and services. Most SatTerms and routers have firmware readily available online (such as [here](https://www.viasat.com/customer-service/bgan-firmware/) or [here](https://www.speedcast.com/support-center/firmware/)). While flipping through various websites, I stumbled across [RedPort](https://www.redportglobal.com/), a company recently acquired by [Pulsar International](https://www.pulsarbeyond.com/). I grabbed firmware for their most popular device, the [wXa-223](https://www.mysatphone.com/products/gmn-wxa-223?srsltid=AfmBOoq4aixmEU2tbhIHy4q05xyTclMqOQI412xMzeUV_Bi78kRlDxGM) and was able to unpack it with binwalk. 

Within 4 minutes, I had pre-auth RCE over LAN...I wish that was a joke.
# Details:
The device has a web-server intended for management functionality and to serve as a GUI for texting / emailing over satellite comms. For authenticated endpoints, the `check_auth` PHP function is used as a guard:

```php
function check_auth(){

	if(! isset($_SERVER['PHP_AUTH_USER'])){
        header('WWW-Authenticate: Basic realm="Private"');
        header('HTTP/1.0 401 Unauthorized');
        echo 'No Username Provided';
		exit;

	}

	$usr=$_SERVER['PHP_AUTH_USER'];
	$cmd = "perl -e '@a=getpwnam(\"$usr\");\$b=join(\",\",@a);print\$b'";

	$pwinfostr="";
	exec($cmd,$pwinfostr);

	// ... code continues ...
?>
```


So...yeah. Take the user-supplied username (`PHP_AUTH_USER`) and throw it right into a perl command. Then just...execute it.

We can escape the command string and then use netcat (included with busybox on the device) to launch a reverse shell

![](/assets/img/img_redport/redport-1.png)

Oh what do you know...it also runs as root.


![](/assets/img/img_redport/redport-2.png)

# Disclosure:
This vulnerability was disclosed through 3 channels - a direct message to two employees as well as a filed support ticket. Each of these was followed-up on..twice. My business partner also *called the office in Tennessee* and was told to try back later...we were subsequently ghosted. ~7 total communication attempts over 90 days with a grand total of *nada* in response.

Soooo this is unpatched. I didn't dig into the device any further (shortest project ever), but there is likely other low-hanging fruit and some juicier attack surfaces outside of the localw web-server.
