# Credentials MSF Plugin

Run all Metasploit POST modules to find credentials inside a session.

## Installation

Just download/clone this repo and execute *install.sh* from its folder.

```bash
git clone https://github.com/carlospolop/MSF-Credentials.git
cp credentials.rb /usr/share/metasploit-framework/plugins/
```

## Load

Once installed, load it inside a running msfconsole session executing:

```
load credentials
```

## Gather Credentials

Once the plugin is loaded you can execute:

**all_creds:** This will execute every single POST module to gather credentials from the system.
```
all_creds -s all
all_creds -s 1
```

**sys_creds:** This will gather only the hashes of the users.
```
sys_creds -s all
sys_creds -s 1
```

## Privesc


## win_privesc

Execute some useful POST modules to find a way to escalate privileges in Windows

```
win_privesc -s all
win_privesc -s 1
```

For more information about privilege escalation in Windows read [Windows Full Local Privilege Escalation Guide](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation)

For more information about privilege escalation in Linux read [Linux Full Local Privilege Escalation Guide](https://book.hacktricks.xyz/linux-unix/privilege-escalation)
