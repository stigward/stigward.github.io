---
title: "AI-Driven Binary Analysis on a TOTOLINK Router - Shooting Bugs-In-A-Barrel"
date: 2025-06-18
description: "Using PRIZM ZERO's AI-driven binary analysis to reproduce known CVEs and find new memory-corruption bugs in a TOTOLINK router's cstecgi.cgi."
tags: [embedded, ai, research, rce]
---
**Original research published on a company blog [here](https://www.prizmlabs.io/post/shooting-bugs-in-a-barrel-with-ai-driven-binary-analysis-on-a-totolink-router)**

---

Last week, we were doom-scrolling [vuldb](https://vuldb.com/) and came across a handful of sequential CVEs published for an old TOTOLINK router. These CVEs were all memory corruption bugs, affecting the cstecgi.cgi binary .  

While developing PRIZM ZERO, our automated vulnerability discovery tool, we regularly test real-world binaries to assess the tool's performance against known positives - this seemed like an excellent opportunity to do just that. Also, given the...less than stellar security track record of the device, we were hopeful to _maybe_ stumble across some unknown true positives as well (spoiler alert, we did).

## Vulnerability Overview:
The vulnerabilities in question were:

- [CVE-2025-5901](https://nvd.nist.gov/vuln/detail/CVE-2025-5901) - Stack buffer overflow in UploadCustomModule
- [CVE-2025-5902](https://nvd.nist.gov/vuln/detail/CVE-2025-5902) - Stack buffer overflow in setUpgradeFW
- [CVE-2025-5903](https://nvd.nist.gov/vuln/detail/CVE-2025-5903) - Stack buffer overflow in setWiFiAclRules
- [CVE-2025-5904](https://nvd.nist.gov/vuln/detail/CVE-2025-5904) - Stack buffer overflow in setWiFiMeshName
- [CVE-2025-5905](https://nvd.nist.gov/vuln/detail/CVE-2025-5905) - Stack buffer overflow in setWiFiRepeaterCfg

The researcher who identified these vulnerabilities included a small RCA and crash PoC for each individual finding. For example, here is the overview of the CVE-2025-5901.

![](https://static.wixstatic.com/media/82b748_31e8956209af4e63b0c4b73b904ab78d~mv2.png/v1/fill/w_740,h_338,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_31e8956209af4e63b0c4b73b904ab78d~mv2.png)

So....yeah. Take user parameter, don't check it, strcpy it into fixed sized buffer. _Look out...y2k is just around the corner!_ The other 4 bugs follow much the same pattern - sometimes with slightly different sinks, but always copying user data directly into a stack buffer without size checks.

Lets see if we can find these with ~ The Power of AI ~.
## Obtaining And Unpacking The Firmware:
The first step of any good IoT hacking project is, of course, to obtain and unpack the firmware. Thankfully, this is pretty easy for TOTOLINK devices. Firmware downloads can be found [on the company site](https://totolink.com.my/products/t10/), and the file system can be unpacked with binwalk. From there, the binary in question is located at /webcste/cgi-bin/cstecgi.cgi. We yoinked that and threw it into PRIZM ZERO.
## How PRIZM ZERO Analysis Works:
In order to better understand PRIZM ZERO (we need a nickname/shorthand, but P0 is taken...sadly), its important to peek under the hood. The tool is built with a handful of program analysis scripts written with Binary Ninja's API. The fundamental idea behind the tooling is high quality inputs to an LLM agent leads to high(er) quality outputs. The goal is to really fine-tune these program analysis scripts to identify legitimate bug candidates.

However, as anyone familiar with this type of work will know, program analysis scripts can be loud - no matter how good they are, they will likely have a relatively high false positive rate.

To combat this, the detections from these scripts are then fed to a custom agent. The agent has access to tooling and can use the disassembly, intermediate language representation, and Single Static Assignment (SSA) form to triage each individual finding and provide a confidence score reflecting the true positive likelihood.

![](https://static.wixstatic.com/media/279f3c_83d9c38469ef4dc2803476769e9a82f0~mv2.png/v1/fill/w_740,h_183,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/279f3c_83d9c38469ef4dc2803476769e9a82f0~mv2.png)
## Results:
When we dropped the binary into PRIZM ZERO and ran the initial analysis, we ended up with 236 initial findings.

![](https://static.wixstatic.com/media/82b748_42149bd20cc940358c8ff0f1f438f039~mv2.png/v1/fill/w_740,h_732,al_c,q_90,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_42149bd20cc940358c8ff0f1f438f039~mv2.png)
After running the triager, the number was paired down to 99. One final round of deduplication, and we ended up at 35. 35 is a _lot_ more manageable to review than 236.

Because the binary is stripped, we needed to find the functions associated with each endpoint handler and compare them with the CVE descriptions. Thankfully that was pretty easy - when we searched for the string, we directly found the associated function handler.
![Yeah, yeah we could have used a slick MCP server for this and done it faster...relax](https://static.wixstatic.com/media/82b748_14df8aeefe8f42cb824f1f10c9a2ccc7~mv2.jpg/v1/fill/w_740,h_167,al_c,q_80,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_14df8aeefe8f42cb824f1f10c9a2ccc7~mv2.jpg)

Yeah, yeah we could have used a slick MCP server for this and done it faster...relax That led us to the following mappings:
- CVE-2025-5901 - UploadCustomModule - sub_41d688
- CVE-2025-5902 - setUpgradeFW - sub_41d47c
- CVE-2025-5903 - setWiFiAclRules - sub_415edc
- CVE-2025-5904 - setWiFiMeshName - sub_2160c
- CVE-2025-5905 - setWiFiRepeaterCfg - sub_4167cc

Then we searched for the corresponding function names in the PRIZM ZERO output. For example, when we looked for sub_41d688 in our 35 findings, we got this hit:

> In sub_41d668 the code unconditionally invokes strcpy(&str, websGetVar(...)). Although &str is large (0x32000 bytes), the length of the JSON File field is attacker-controlled and not bounds-checked before the strcpy. This allows a remote overflow of the stack buffer, leading to potential code execution.

Comparing that to the original vulnerability description provided by the researcher:

> In the T10 V2_Firmware V2_V4.1.8cu.5207 firmware has a buffer overflow vulnerability in the UploadCustomModule function. The v8 variable receives the File parameter from a POST request. However, since the user can control the input of File, the strcpy(v15, v8); can cause a buffer overflow vulnerability.

That's actually...pretty good.

Similarly, the tool was able to spot CVE-2025-5903, CVE-2025-5904, and CVE-2025-5905 - you can see the output on the PRIZM ZERO [Vuln Discoveries](https://zero.prizmlabs.io/vuln-discoveries)  page.

Those with a keen eye will notice _CVE-2025-5902 is no where to be seen._ And you would be correct - we'll come back to that in a second.
### The Other Findings
Okay - what about the other findings? We started with 35, and we have now reviewed 4 off the list. In addition, 2 of the findings were just potential NULL derefs based on not checking environment variables:

> The code calls strtol(getenv(\"CONTENT_LENGTH\"), …) without checking if getenv returned NULL. In a CGI context, CONTENT_LENGTH may be unset (e.g., on a GET request), causing getenv to return NULL and leading to a NULL pointer dereference when passed to strtol. This is a real issue that can crash the CGI application (denial-of-service).

Not necessarily a false positive, but also certainly not very interesting. So we will ditch those. That leaves us with 29.
### CVE Situation
TOTOLINK has this really fun quirk where they just actively decide not to patch remotely exploitable bugs in their webserver, even if they are actively [targeted by botnets](https://www.fortinet.com/blog/threat-research/new-rust-botnet-rustobot-is-routed-via-routers). So, even though we ran this on the most up-to-date software release, quite a few of the remaining bugs were already known N-days.

Results are included below - **at least** 11 of our 27 true positive findings were associated with a CVE (sort-of). Often, they were associated with multiple CVEs across a range of years, since:

1. TOTOLINK doesn’t respond to disclosures or active exploitation
2. CVE is broken

It’s also quite possible that other true positives included here have already been reported, and just had vague CVE descriptions. That said, we did our best to map descriptions back to our own findings. The table below is color-coded - green means we were able to easily trigger the bug in our emulated environment, yellow means the bug itself exists, but the trigger would be dependent on device configuration, and red is a false positive.

We would generally be hesitant to drop 0-days, but given the findings and the consistent [lack](https://github.com/SpikeReply/advisories/blob/main/cve/totolink/cve-2024-27521.md) of vendor response for the last 3 years, the T10 should be treated as EOL from a security perspective at this point. We _will,_ however, refrain from dropping full PoCs.
### Command Injection Vulnerabilities

|            |                   |                                        |                                                  |
| ---------- | ----------------- | -------------------------------------- | ------------------------------------------------ |
| Function   | Endpoint          | Description                            | Human Triage                                     |
| sub_41f89c | setNoticeCfg      | noticeUrl parameter command injection  | [True Positive] - CVE-2025-28035, CVE-2025-28036 |
| sub_41c90c | informSlaveUpdate | echo command with unescaped user input | [True Positive] - No CVE                         |
| sub_4267a0 | N/A               | arg1 parameter command injection       | [False Positive] - Dead Code                     |
| sub_427d3c | N/A               | md5sum command injection               | [False Positive] - Not attacker controlled       |
### Memory Corruption Vulnerabilities

|            |                      |                                                 |                                                                         |
| ---------- | -------------------- | ----------------------------------------------- | ----------------------------------------------------------------------- |
| Function   | Endpoint             | Description                                     | CVE                                                                     |
| sub_4263e8 | setIpv6WanCfg        | overflow with routername parameter              | [True Positive] - No CVE                                                |
| sub_42131c | setWiFiWpsStart      | overflow with WPS PIN                           | [False Positive] - Conditional Constraint                               |
| sub_4166b8 | setIpv6LanCfg        | overflow with dnsAddr, potrName parameters      | [True Positive] - No CVE                                                |
| sub_41c90c | informSlaveUpdate    | 512-byte buffer overflow                        | [True Positive] - No CVE                                                |
| sub_41f704 | setTracerouteCfg     | overflow with command parameter                 | [True Positive] - Related to - CVE-2023-30013 - see below               |
| sub_41f7d0 | setDiagnosisCfg      | overflow with ping command                      | [True Positive] - Related to CVE-2022-28908, CVE-2025-28037 - see below |
| sub_41f89c | setNoticeCfg         | overflow with noticeUrl                         | [True Positive] - Related to CVE-2025-28035, CVE-2025-28036 - see below |
| sub_42160c | setWiFiMeshName      | overflow in haystack buffer                     | [True Positive] - CVE-2025-5904                                         |
| sub_415658 | setIpPortFilterRules | overflow to 3-byte buffer                       | [True Positive] - CVE-2022-36488, CVE-2024-1002                         |
| sub_415edc | setWiFiAclRules      | overflow with desc                              | [True Positive]                                                         |
| sub_415afc | setParentalRules     | overflow to 0x40-byte buffer with desc          | [True Positive] - CVE-2024-8574, CVE-2024-7333                          |
| sub_41631c | setWiFiScheduleCfg   | overflow with desc                              | [True Positive] - No CVE                                                |
| sub_4167cc | setWiFiRepeaterCfg   | strcpy WEP passphrase overflow                  | [True Positive] - CVE-2025-5905                                         |
| sub_41aae8 | setPortForwardRules  | overflow 64-byte input to 24-byte buffer        | [True Positive] - Constrained                                           |
| sub_4227cc | setRadvdCfg          | overflow with radvdPotrName                     | [True Positive] - No CVE                                                |
| sub_41d668 | UploadCustomModule   | overflow with file name                         | [True Positive] - CVE-2025-5901                                         |
| sub_417370 | setipv6WanCfg        | 20-byte write to 4-byte buffer                  | [True Positive] - No CVE                                                |
| sub_424c54 | N/A                  | fgets with 0x3ff size to 0x40 buffer            | [True Positive] - Constrained                                           |
| sub_424fbc | N/A                  | unbounded buffer write in parsing loop          | [True Positive] - Constrained                                           |
| sub_405178 | N/A                  | overflow in mesh_assoc_mpinfo                   | [True Positive] - Constrained                                           |
| sub_404d7c | N/A                  | strcpy overflow by 4 bytes                      | [True Positive] - Constrained                                           |
| main()     | Main CGI Handler     | overflow in str_1 buffer with JSON construction | [True Positive] - Constrained                                           |
| sub_405bf0 | getWiFiMeshConfig    | overflow                                        | [True Positive] - Constrained                                           |
| sub_408484 | getSmartQosCfg       | strcpy from 64-byte buffer to 4-byte var        | [True Positive] - Constrained                                           |
| sub_4267a0 | N/A                  | overflow in 128-byte buffer                     | [False Positive] - Dead code                                            |
| sub_423f5c | N/A                  | overflow in /proc path construction             | [False Positive] - Not attacker controlled                              |
| sub_414b68 | setWiFiWpsCfg        | overflow with wifiIdx parameter                 | [False Positive] - Not a vulnerability                                  |
| sub_40f738 | getIpPortFilterRules | strcpy overflow with desc field                 | [False Positive]                                                        |
| sub_407f80 | getUrlFilterRules    | strcpy from 88-byte to 64-byte buffer           | [False Positive] - Not Attacker Controlled                              |
## Interesting Findings:

### The Good
When manually reviewing the findings, there were clear examples where the agent was able to perform steps similar to a human triage workflow. For example, take the bug in sub_424c54. When manually triaging, we initially planned to mark this as a false positive. However, looking back at the agent’s thought process, it had the following description:

> The function sub_424c54 calls fgets(str, 0x3ff, stream) where str points to a local stack buffer of only 0x40 bytes (64 bytes). This is a clear stack buffer overflow. In practice, the input comes from /proc/net/route, which is generated by the kernel and not under attacker control, making exploitation unlikely. However, it remains a real bug (unsafe use of fgets) that could lead to stack corruption and potential crashes.

Hard to argue with the reasoning. Not only that, but it changed the recommended severity suggested by the program analysis script, moving it from a HIGH to a LOW based on the new context. Another good example of this is the OOB Write Bug in setipv6WanCfg. The agent provides the following description:

> In sub_417370 the code writes up to 20 bytes into the buffer pointed to by arg2 (offsets 0 through 19). In the caller sub_4231b0, arg2 is &var_12c, a 4-byte int32_t on the stack. This mismatch leads to a real out-of-bounds write of at least 16 extra bytes, corrupting the stack and enabling potential control-flow hijack.

Here, it demonstrates the ability to trace data-flow across multiple function calls, referencing the call-stack and keeping track of different variables and their sizes.
### The Bad

Sometimes though, the agent totally whiffs - even on seemingly easier RCAs than the ones above. For example, take the supposed command injection in sub_427d3c . The following description is provided:

> The function sub_427d3c constructs a shell command via sprintf: \"md5sum %s | cut -d ' ' -f0 \", using the untrusted arg1 directly into the command line. The resulting string is then passed to getCmdStr, which invokes a shell or system call to execute the command. An attacker controlling arg1 can inject arbitrary shell metacharacters (e.g., \"; rm -rf /\"), leading to command injection and full code execution.

But, one look at the cross references tells you arg1 is always hard-coded - so this would never be exploitable. Sometimes, it even confidently states information about the call stack which is blatantly incorrect. Take the reasoning from the sub_423f5c finding:

> The function sub_423f5c allocates a fixed 0x44-byte (68) buffer (var_58) and then calls sprintf(var_58, \"/proc/%s/mesh_assoc_mpinfo\", arg2) without any length check on arg2. Since arg2 is fully attacker-controlled (it is sourced from unbounded web-request data), a string longer than ~43 characters will overflow var_58, leading to a stack-based buffer overflow. No bounds checking mitigates this, making it a real high-severity issue.

This function only has one xref at memory address 0x404e40  and it reads sub_423f5c($a0_2, "wlan0").

![](https://static.wixstatic.com/media/82b748_3e45bb0cf8924c1eaaf914028d711783~mv2.png/v1/fill/w_740,h_116,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_3e45bb0cf8924c1eaaf914028d711783~mv2.png)

I don’t know about you, but I don’t see a “fully attacker-controlled” arg2 from “an unbounded web-request”. The full PRIZM ZERO output is included on our [GitHub](https://github.com/PrizmLabs-io/blogs-and-exploits/blob/main/bugs-in-a-barrel/prizm_zero_output.json) for further review - overall, there were 8 false positives. We certainly have room for fine-tuning, but for a pre-alpha, it’s not bad.
### Missing True Positives?
**The Missing CVE-2025-5902**

The elephant in the room will be missing true positives. In an effort to reduce the noise, how many real vulns did we kill? To be perfectly honest, there is no great way to test this with the available information. That said, we can start with CVE-2025-5902 - the missing bug we promised to get back to earlier.

The description included in the original researchers reads as follows:

> In the T10 V2_Firmware V2_V4.1.8cu.5207 firmware has a buffer overflow vulnerability in the setUpgradeFW function. The v6 variable receives the slaveIpList parameter from a POST request. However, since the user can control the input of slaveIpList, the sprintf and system can cause a command injection vulnerability.

So, allegedly we're missing an overflow AND a command injection. Interestingly enough, when we compare the researchers' vulnerable firmware and our firmware, we see quite a big difference - and it doesn’t seem to just be a difference in Binary Ninja vs Ghidra:

Here is the original post's included image:

![](https://static.wixstatic.com/media/82b748_de7857629b664db290228bd2901ff1e4~mv2.webp/v1/fill/w_740,h_402,al_c,q_80,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_de7857629b664db290228bd2901ff1e4~mv2.webp)

Andddd here is what we see in our binary decomp:

![](https://static.wixstatic.com/media/82b748_f078c071ace84dc19fe297ac7650f72d~mv2.jpg/v1/fill/w_740,h_258,al_c,q_80,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_f078c071ace84dc19fe297ac7650f72d~mv2.jpg)

As you can see, in the firmware we are assessing, the endpoint handler has a fixed string for the system call, and does not try to construct fwSyncUpgIpList as in the original research. Not only that, but the sprintf in our decompilation is actually - believe it or not - safe since the format specifier is %d.

So in this case, we don’t detect CVE-2025-5902 because it's not actually present in our binary.

**Aggressive De-duplication**

Quite a few missing bugs resulted from an over-aggressive de-duplication effort. This was made abundantly clear, when cross referencing CVEs. Take, for example a bug and a pattern that was initially handled correctly: the command injection and the overflow associated with informSlaveUpdate . Here is the associated code:

![informSlaveUpdate endpoint handler](https://static.wixstatic.com/media/82b748_c43bc0319c7146e7aec7f435c2f315ca~mv2.jpg/v1/fill/w_740,h_187,al_c,q_80,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_c43bc0319c7146e7aec7f435c2f315ca~mv2.jpg)

informSlaveUpdate endpoint handler

You can clearly see the sprintf, which could lead to an overflow, followed by the system call, which clearly leads to command injection. The same is true for setNoticeCfg, where we clearly retained both the overflow and the command injection in our final list.

However, on de-duplication of both setDiagnosisCfg and setTraceRouteCfg, we remove the command injection finding despite it clearly following right after overflow. Looking back at the analysis, the de-duplication engine determined these were the same bug, and tried to consolidate them down. There were just too many bugs-in-the-barrel.

![setDiagnosisCfg endpoint handler](https://static.wixstatic.com/media/82b748_e900a56d69f241d48b15262f6d2f6e1a~mv2.jpg/v1/fill/w_740,h_215,al_c,q_80,usm_0.66_1.00_0.01,enc_avif,quality_auto/82b748_e900a56d69f241d48b15262f6d2f6e1a~mv2.jpg)

setDiagnosisCfg endpoint handler
## Learnings And Takeaways:
The experiment proved useful for new focus areas as we continuously improve PRIZM ZERO, specifically:

1. Our program analysis scripting. The more bug classes we can model, and the more information we can provide to our agents, the better. This is notoriously difficult for more complex bug classes, but we are actively working on improving our detection daily.
2. Agent fine-tuning, specifically around data flows and cross-references. There are strokes of brilliance, and strokes of complete hallucinations. Figuring out how to get more of the former and less of the latter is an important focus of our continuous R&D efforts.
3. De-duplication. Maybe making it just a _touch_ less aggressive.
