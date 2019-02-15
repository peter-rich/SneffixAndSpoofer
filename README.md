# SneffixAndSpoofer
## Zhanfu Yang, yang1676@purdue.edu

## Task 1
### Complie
	gcc -Wall -o sniffex sniffex.c -lpcap

### Run 
	Machine B(192.168.5.5): sudo ./sniffex
	Machine A(192.168.5.4): ssh -p 23 cs528user@localhost 
				Enter the password.
	

## Task 2
### Compile

	gcc -o spoofer spoofer.c

### Run
	In spoofing machine: 192.168.5.5:

	sudo ./spoofer

	Opt:
		1: ICMP Mode for Task2.b
		2: Ethernet Mode for Task2.c
	
	In detection machine: 192.168.5.4

	Task2.b:   sudo tcpdump -XX icmp
	Task2.c:   sudo tcpdump -eXX ether host 01:02:03:04:05:06

## Task 3
### Compilation
	gcc -Wall -o sniffex-spoofer sniffex-spoofer.c -lpcap

### Run the program	
	In machine B(192.168.5.5): sudo ./sniffex-spooper

	In machine A(192.168.5.4): ping unknown IP or public IP
