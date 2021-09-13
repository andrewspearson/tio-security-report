# tio-security-report
tio-security-report.py reports the security configuration of all user accounts on tenable.io.

With this tool you can identify all single factor ways into your tenable.io.

## Requirements
* Python 3.3 or later
## Installation
tio-security-report.py is a dependency free, standalone Python program. Just download it and run it.
### git
```
$ git clone https://github.com/andrewspearson/tio-security-report.git
```
### curl
```
$ curl https://raw.githubusercontent.com/andrewspearson/tio-security-report/main/tio-security-report.py -O
```

**NOTE:** macOS users running Python 3.6+ will need to [install certificates](https://bugs.python.org/issue28150).
TLDR, run this command:
```
$ /Applications/Python {version}/Install Certificates.command
```
This seems to only be an issue on macOS.
## Usage
tio-security-report.py must run as a Tenable.io Administrator. You can run it with API keys or username/password authentication.

tio-security-report.py will first look for a file named tenable.ini with API keys. If it does not find this file or if the file does not contain API keys, then tio-security-report.py will prompt the user to enter a username, password, and possibly two factor authentication code.

It will accept arguments to set a web proxy and disable SSL verification, like this:
```
$ tio-security-report.py --proxy '127.0.0.1:8080' --insecure
```
These arguments are not required. Disabling SSL verification is HIGHLY discouraged.

## Output
A CSV report will be created in the working directory.
