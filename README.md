Lab1 README:
Course: CS452

Lab1 Basic Usage:

Build everything from the command line
each in it's own terminal window:
(On thing1) make clean && make && clear && ./key
(On thing1) clear && ./recv
(On thing2) clear && ./init

You can use the following as a make file:
=============== BEGIN MAKEFILE==============
all: key init recv

key: key.o
	g++ -o key key.o
key.o : KeyDistributionCenter.cc
	g++ -c -std=c++11 KeyDistributionCenter.cc -o key.o -Wall
init : init.o
	g++ -o init init.o
init.o : InitiatorA.cc
	g++ -c -std=c++11 InitiatorA.cc -o init.o -Wall
recv : recv.o
	g++ -o recv recv.o
recv.o : ResponderB.cc
	g++ -c -std=c++11 ResponderB.cc -o recv.o -Wall
clean :
	$(RM) *.o
	$(RM) key
	$(RM) init
	$(RM) recv
============= END MAKEFILE ================

All 3 processes will be running now
The prompts need to be completed in the following order:
NOTE: Order is critical here.
1. Enter all prompts for key
2. Enter all prompts for recv
3. Enter all prompts for init

(The secure connection steps will complete automatically at this point
 between int and recv)

4. Init will now prompt for what either a string or a file path
5. Recv will store the result in a file in /tmp/networks

To enable debugging output:
uncomment #define DEBUG in InitiatorA.cc, KeyDistributionCenter.cc, and ResponderB.cc

If you wish to output non encrypted data between Init and Recv:
uncomment #define #define DO_NOT_DECRYPT_FILE and #define DO_NOT_ENCRYPT_FILE in InitiatorA.cc and ResponderB.cc

If you wish to see the actual plain text output from the process in Recv:
uncomment #define DEBUG_PLAIN_TEXT in ResponderB.cc
NOTE: Doing this an attempting to transfer binary files will cause ternimal issues due to outputting control characters

Test Cases:
Run with auto generated Ks, NonceA, NonceB
Run with manual Ks, NonceA, NonceB
Run with 1mb file from /tmp (dd if=/dev/urandom of=file.txt bs=1048576 count=1)
Run with 256mb file from /tmp (dd if=/dev/urandom of=file.txt bs=1048576 count=256)
Run with 1G file from /tmp (dd if=/dev/urandom of=file.txt bs=1048576 count=1024)
Run with 4G file from /tmp (dd if=/dev/urandom of=file.txt bs=1048576 count=4096)
Run with user input string ("Test input string to confirm encrypted and transfer")
