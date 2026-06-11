---
title: "Uncovering a 0-Click RCE in the SuperNote Nomad E-ink Tablet"
date: 2025-04-06
description: "Chaining a vulnerability and misconfigurations into a remotely installable, 0-click rootkit on the SuperNote Nomad E-ink tablet (CVE-2025-32409)."
tags: [android, research, rce]
---
**Original research published on a company blog [here](https://www.prizmlabs.io/post/remote-rootkits-uncovering-a-0-click-rce-in-the-supernote-nomad-e-ink-tablet)**
## Overview:

Last year, popular E-Ink tablet vendor [Ratta Software](https://supernote.com/?srsltid=AfmBOorepWN3BO2e0u-Dt06zM5pFb1_2q-cAltdVxHU2wKIon0WtcJ0C) released the [SuperNote A6 X2 Nomad](https://supernote.com/products/supernote-nomad?srsltid=AfmBOop-tkBYaFOtxlwRqT74E3lyC5aV5tvKEzPdwuGEqww6UhyOrBk-) - a 7.8 inch tablet running Android 11 under the hood.

As productivity nerds, we picked one up in July of 2024 with the goal of using it for its intended purpose: note taking and academic paper reading. However, as hackers at heart, it took all of 24-hours before we abandoned that idea entirely and decided to poke at it.

What follows is a blog post detailing how we were able to chain a vulnerability and a handful of misconfigurations into a remotely installable, 0-click rootkit. A malicious attacker on the same network as the victim could fully compromise the target device without any user-interaction. EDIT: This issue was assigned to [CVE-2025-32409](https://nvd.nist.gov/vuln/detail/CVE-2025-32409) after publication.

![](https://static.wixstatic.com/media/82b748_97196ebf509f4c55b79dc58becb3cb8a~mv2.jpg/v1/fill/w_740,h_365,al_c,q_80,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_97196ebf509f4c55b79dc58becb3cb8a~mv2.jpg)
## Recon:
This research kicked off with an innocent Nmap scan, just to see if anything interesting was listening on the device while in its default configuration. Lo and behold, there was one result which stood out:

![](https://static.wixstatic.com/media/82b748_dad176ba78834c66a13db5c0bd162004~mv2.png/v1/fill/w_740,h_114,al_c,lg_1,q_85,enc_avif,quality_auto/82b748_dad176ba78834c66a13db5c0bd162004~mv2.png)

As shown above, we found port 60002 open and listening. Nmap was unable to identify the service directly, so we decided to investigate this mysterious port a bit further by grabbing a firmware image for the device from Ratta Software's ["Updates" page](https://support.supernote.com/en_US/change-log/how-to-update-your-supernote).

The firmware was unencrypted, and we were able to mount the various filesystem images and grep through them for anything related to that port number.
This led us to the _SuperNoteLauncher.apk_, which we threw into [jadx](https://github.com/skylot/jadx) and started reversing.
### Reversing The SuperNoteLauncher  
#### Locating The Port:
After opening the apk in jadx, we first searched for where that port number was specifically being referenced. As shown below, this led us to a _static final int_ named _COMMAND_RECEIVE_FILE_PORT_.

![](https://static.wixstatic.com/media/82b748_deaef05a4efa48bfbb82745ae6f2df98~mv2.png/v1/fill/w_740,h_329,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_deaef05a4efa48bfbb82745ae6f2df98~mv2.png)

Looking for cross-references, we eventually tracked down where it was being used: _com.ratta.supernote.wifip2p.receive_.

![](https://static.wixstatic.com/media/82b748_6d7076b80bce459f8f521d9bdb05b8f4~mv2.jpg/v1/fill/w_740,h_354,al_c,q_80,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_6d7076b80bce459f8f521d9bdb05b8f4~mv2.jpg)
#### Identifying The Service:
At this point, our goal was to better understand the service running on 60002. We can see in the below screenshot that when the port is open, a handful of functions are triggered after something is received over the _ServerSocket_. Specifically, the code of interest resides in the _DeviceThread_ class.

![](https://static.wixstatic.com/media/82b748_ff6953aac3e54d6c9f3e02c17b97f28d~mv2.jpg/v1/fill/w_740,h_117,al_c,q_80,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_ff6953aac3e54d6c9f3e02c17b97f28d~mv2.jpg)

_DeviceThread_ implements _Runnable_ and its r_un()_ function is a behemoth. That said, a quick glance at it indicates that we are likely dealing with a custom HTTP server based on the way error messages are communicated back to the client.

![](https://static.wixstatic.com/media/82b748_a3884e1f5c384c49aae32ce809b22da7~mv2.jpg/v1/fill/w_740,h_257,al_c,q_80,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_a3884e1f5c384c49aae32ce809b22da7~mv2.jpg)

The first line of _run()_ passes the socket over to _getDeviceName()_.

![](https://static.wixstatic.com/media/82b748_bc4db5d9fa99471d909a0dc3e5bf29e4~mv2.png/v1/fill/w_740,h_119,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_bc4db5d9fa99471d909a0dc3e5bf29e4~mv2.png)

![](https://static.wixstatic.com/media/82b748_a3fd6042d0db4b498f707a502678a967~mv2.png/v1/fill/w_740,h_490,al_c,q_90,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_a3fd6042d0db4b498f707a502678a967~mv2.png)

Those of you with a keen eye can probably tell what this is code is doing: parsing out custom headers that our HTTP server expects. This puts into context quite a bit of the strange behavior observed inside _run()_ - different operations are being triggered based on what custom headers are passed from the client.

For example, we can trigger a 501 error code by providing a _version_ header greater than 1

![](https://static.wixstatic.com/media/82b748_f1c608431cc141f29e6c473cd4bb326f~mv2.png/v1/fill/w_740,h_257,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_f1c608431cc141f29e6c473cd4bb326f~mv2.png)

![](https://static.wixstatic.com/media/82b748_b86a2d869c0649348639bbb4fd11bfce~mv2.png/v1/fill/w_740,h_150,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_b86a2d869c0649348639bbb4fd11bfce~mv2.png)

And, when we send the request, we actually get a pop-up error saying that the SuperNote device is not on the latest version

![](https://static.wixstatic.com/media/82b748_2a0a89b77b4241ed92905a46aabeec5b~mv2.jpg/v1/fill/w_350,h_465,al_c,q_80,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_2a0a89b77b4241ed92905a46aabeec5b~mv2.jpg)
### File Uploading
All of this is interesting, but what piqued our interest most was the class names: _RecieverManager_ and _WiFiP2PService_. Unauthenticated device-to-device file sharing sounds like a potentially great attack surface.

Given that we at-least know how to interact with the server, at this point we went ahead and mocked up a python client that just sends a POST request with an attached file and all the necessary headers...andddd the file showed up on the device in the INBOX directory!
![](https://static.wixstatic.com/media/82b748_04d4622d0d594985b6a1653c54feb1a4~mv2.png/v1/fill/w_740,h_418,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_04d4622d0d594985b6a1653c54feb1a4~mv2.png)

![](https://static.wixstatic.com/media/82b748_7bc40303171c4df2acfaeafa61cc6664~mv2.jpg/v1/fill/w_740,h_702,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_7bc40303171c4df2acfaeafa61cc6664~mv2.jpg)

![](https://static.wixstatic.com/media/82b748_f8bbae3bde50411299f6479d791c2266~mv2.jpg/v1/fill/w_740,h_557,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_f8bbae3bde50411299f6479d791c2266~mv2.jpg)
## Investigating A Path Traversal:
After figuring out how to get files into the INBOX directory, we did what all good security researchers would do: added some "dot-dot-slashes" to our payload to see what would happen. Specifically, the Nomad has a directory named EXPORT at the same level as INBOX. This EXPORT directory is accessible in the UI, allowing us to quickly verify if the payload worked. Our new headers dict includes the path traversal payload, like so:

headers = {"version": "1", "content-length": "1234", "name": "../../../../../../../../sdcard/EXPORT/testfile.txt", "devicename": "testdevice"} And what do you know? It worked!

![](https://static.wixstatic.com/media/82b748_b1aab90cb7b14c48872987d985234a37~mv2.jpg/v1/fill/w_740,h_656,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_b1aab90cb7b14c48872987d985234a37~mv2.jpg)

  

However, see that pesky "_(1)"_ appended to the end of our filename? Yeah, that is going to prove to be quite the problem during exploitation here in a second.
### Exploit Plan:
Up until now, we haven't been entirely honest. Going into this, we had a little bit of an idea as to what an exploit _might_ look like if we were able to find an arbitrary file write. This idea stemmed from 3 critical pieces of information we came across during our recon.

1. SuperNote's instruction on the Firmware Update page specifically ask you to put the downloaded zip file into the EXPORT directory
2. A manual firmware update will automatically start after a hotplug event or reboot if a valid update image is found in the EXPORT directory
3. A researcher [poked at the previous generation of SuperNote devices](https://github.com/TA1312/supernote-a5x) and found that firmware images were signed with publicly available debug keys and the bootloader was unlocked by default...nice. We confirmed that while the keys had been renamed on the newer devices, they were still the same.

Therefore, we figured we could do the following:  

4. Create a backdoored firmware image and sign it with the publicly available debug keys
5. Use the arbitrary write to get the download directly into the "EXPORT" directory
6. An update would automatically be initiated during normal device usage, installing our malicious rootkit.

This was all good in theory, only there was one major problem
### The Problem
Remember that "_(1)_" appended to our filename? Yeah, here is where it comes back to bite us. You see, the service that scans for the update in the EXPORT directory has the following code:

![](https://static.wixstatic.com/media/82b748_61fcdb7519074a7d87bb0e9652edf8c8~mv2.jpg/v1/fill/w_740,h_117,al_c,q_80,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_61fcdb7519074a7d87bb0e9652edf8c8~mv2.jpg)

The filename has to be exactly _update.zip_...not _update(1).zip_. So we need to figure out _why_ the extra number gets appended to our path traversal payload and how we can get rid of it.
#### Why Does The Filename Change?
After a bit more reverse engineering of the launcher apk, we finally determined the root cause of the issue. While it would be too much code to include via screenshots here, the high-level file reception logic is as follows:

1. The server first creates a file in its application directory under the "_/_receiver__file_cache/file_name_" path
2. It then copies the incoming stream of data into that newly created file in "receiver__file_cache/file_name_" path
3. When it has reached the end of the incoming stream of data, it then creates a new file, named `INBOX/file_name`
4. It copies the contents from "receiver__file_cache/file_name"_ over to "_INBOX/file_name"_
5. Finally, it deletes the cached file.

The problem arises due to the continued use of the attacker supplied filename for _all_ operations. So for our original attack plan, what ACTUALLY ends up happening on the device is:

1. The server receives and creates the "_/_receiver__file_cache/../../../../sdcard/EXPORT/update.zip_" file, thinking this should be the cache file
2. Then after it has finished receiving the data, it goes to create the INBOX file, but actually attempts to create "_/INBOX/../../../../sdcard/EXPORT/update.zip_" again

Before each file creation event, the following code is run:

![](https://static.wixstatic.com/media/82b748_030c9ba864324cf38bb456dd16f18c2d~mv2.png/v1/fill/w_740,h_354,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_030c9ba864324cf38bb456dd16f18c2d~mv2.png)

As shown, if the name already exists where a new file is to be written, then a "1" (or the next subsequent number) is added to the file name. So instead of creating "_/EXPORT/update.zip_", the 2nd file creation event creates "_EXPORT/update(1).zip_". Then the remaining steps of the process take place: the file contents are copied over, and the the original file ("_/EXPORT/update.zip_") is deleted, leaving us only with the renamed one.  

## Finding A Naming Issue Bypass Via A "Race Condition"

So given our current strategy, we are stuck. We need to figure out how to get our actual update file into EXPORT with the right name. At this point, we spent a lot of time trying to find an actual naming bypass, which naturally didn't work. What _did_ end up working was taking advantage of a logical "race condition"...technically it's not _actually_ a vulnerability or a traditional race condition, but we can leverage it to our advantage.

You see, a legitimate update file is 1.1GB large. That means, it takes quite a bit of time to transfer. Three other factors also play to our advantage:

1. The file is first created, and then the stream is written byte-by-byte into it.
2. Once the transfer completes, the second file is created, and then the copy starts.
3. The server is multi-threaded, meaning it can receive multiple files at the same time

We can use these three facts to modify our exploit a bit.
### Revised Exploit Strategy:
Using our understanding of the server logic under the hood, we can use the following trick to satisfy our naming requirements.
1. Create a very small, dummy file named `update.zip`
2. Create a legitimate `update.zip` file that contains our malicious backdoor, signed with the publicly available development keys
3. Send the the very small, dummy file first
4. Send the legitimate `update.zip` file immediately after.

Anddd if we do that, the following happens on device (Note - thread one is _italicized_ and thread two is **bold**):  

1. _`EXPORT/update.zip` is created by the dummy file during the caching / initial reception step_
2. **`EXPORT/update(1).zip` is created by the real update during the caching / initial reception step**
3. _`EXPORT/update(2).zip` is created by the dummy file during the copy step_
4. _`EXPORT/update.zip` is deleted by the dummy file after completion of the copy step_
5. **`EXPORT/update.zip` is created by the real update during copy step**
6. **`EXPORT/update(1).zip` is deleted by the real update after completion of copy step**
Because our dummy file is so much smaller than the real update file, it completes the caching, copy, and delete steps before the valid update is done being recieved. This leaves the _EXPORT/update.zip_ name available when the copy step begins for the valid update.  

So, after our exploit runs, we are left with a properly named malicious update image. We also have the "_EXPORT/update(2).zip"_ artifact left over from our dummy file's copy operation, but we don't care about it. If we want to do clean-up, that could be performed after the rootkit is installed.
## Backdooring The Firmware Image
We won't go too in-depth on this step, but we found the development keys needed after a bit of Googling around. From there, we created a backdoor using [flashable-android-rootkit](https://github.com/ng-dst/flashable-android-rootkit) and writing simple C reverse shell payload. To re-package the firmware, we followed the recommended method from the [previous research](https://github.com/TA1312/supernote-a5x?tab=readme-ov-file#build-and-sign-your-own-updatezip) and used [Multi Image Kitchen](https://forum.xda-developers.com/t/kitchen-windows-multi-image-kitchen-repack-android-partitions.4326387/) (Note: Finding the right JDK version to get Multi Image Kitchen working was one of the harder parts of this exploit).
## Putting It All Together
Once the payload is in position, it will be auto-installed during normal operations of the device. The installer checks the EXPORT directory during hotplug events (usb-c in or out of the device) or during a reboot. Therefore, all you have to do is sit back, wait, and hope the user doesn't find the potentially suspicious update.zip file in EXPORT. Note that after a hotplug event, the user DOES get a prompt about an update. However, it is an opt-OUT prompt, meaning the update will install in 30 seconds unless "abort" is clicked. If all goes according to plan, you get the following:

![](https://static.wixstatic.com/media/82b748_0b427783183149029b4d36bbf134e381~mv2.jpeg/v1/fill/w_740,h_346,al_c,q_80,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_0b427783183149029b4d36bbf134e381~mv2.jpeg)

## Disclosure Timeline:
- **July 26, 2024** - PRIZM reaches out to Ratta Software's service team
- **August 15th, 2024** - PRIZM follows up with Ratta Software
- **September 23rd, 2024** - PRIZM follows up with Ratta Software again, notifying them of plans to publicly disclose the vulnerability at the 90 day disclosure deadline (Oct 23rd)
- **September 30th, 2024** - PRIZM loops in Ratta software's "feedback" team in an effort to get a response.
- **October 2nd, 2024** - Ratta Software responds, mentioning staff changes had caused the disclosure to slip through the cracks. Team asks for additional information to pass to their head of engineering.
- **October 3rd, 2024** - PRIZM provides a 7 page technical report, including full exploit code for local reproduction
- **October 15th, 2024** - PRIZM follows up to ensure the technical details have been recieved and remind of the upcoming 90 day deadline the following week.
- **October 16th, 2024** - SuperNote responds and mentions they plan to address the issues in the December update.
- **October 16th, 2024** - PRIZM replies and agrees to hold off on any disclosure until December 2024.
- **EDIT: April 8th, 2025 -** [CVE-2025-32409](https://nvd.nist.gov/vuln/detail/CVE-2023-30257) was assigned.
