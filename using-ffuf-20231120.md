# Using `ffuf`

## Brute-forcing Login Forms

To brute-force the password for a POST-based login form, check first using Burp and then plug the appropriate parameters into a command like this:

```text
ffuf -w /usr/share/seclists/Passwords/xato-net-10-million-passwords-10.txt:FUZZ -u http://${t}/example/admin.php -X POST -d 'username=admin' -d 'password=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -ac
```

```console
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://${t}/ -H 'Host: FUZZ.example.htb' -ac
```

## Fuzzing Subdomains

A standard approach to finding subdomains might look something like this:

```console
ffuf -w ~/seclists/Discovery/DNS/n0kovo_subdomains.txt -u http://mentorquotes.htb -H 'Host: FUZZ.mentorquotes.htb' -ac
```

That approach works fine in many cases, although a valid subdomain might return 404, in which case that above command wouldn't catch it since it filters our that error code. I learned this on [htb-mentor-20241218](htb-mentor-20241218.md), where the following command was needed to catch the subdomain I needed:

```console
$ ffuf -w ~/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://mentorquotes.htb/ -H 'Host: FUZZ.mentorquotes.htb' -mc all -fw 18
...
api                     [Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 101ms]
#www                    [Status: 400, Size: 308, Words: 26, Lines: 11, Duration: 94ms]
#mail                   [Status: 400, Size: 308, Words: 26, Lines: 11, Duration: 96ms]
:: Progress: [19966/19966] :: Job [1/1] :: 420 req/sec :: Duration: [0:00:48] :: Errors: 0 ::
```

Note the `-mc all` and `-fw 18` (filter word-counts) flags.
