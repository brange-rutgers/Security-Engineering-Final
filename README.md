# Security-Engineering-Final
Welcome to the Rutgers 2016 Security Engineering final project.
The source code is available at https://github.com/brange-rutgers/Security-Engineering-Final

In this project we implemented a software simulation of a man in the middle attack on the communication between a SIM card and device, assuming that the MITM had access to read, modify, and block packets in either direction.

This project was implemented on debain based linux, ie Ubuntu, Mint

Crypto++ libraries install

sudo apt-get install libcrypto++9 libcrypto++9-dbg libcrypto++-dev

The demo does not require click, only the crypto++ libraries.

To try and play around with the click code, install click with instructions from here : http://www.read.cs.ucla.edu/click/tutorial1

See the license.txt file for license details.


To compile the demo, in the demo directory run g++ main.cpp Node.h Node.cpp -o YOUR_EXECUTABLE_NAME_HERE -lcryptopp -std=c++11
The demo will prompt for an "enter" to proceed to different stages in the program. If it looks like the program is hung up, press enter. Keep an eye out for the line "Enter input for sim to send to device:". You don't want to press enter immediately here, enter your own testing string, ie: "Hello please give me an A"

To compile the click WIP code, run make in the click directory

KNOWN BUGS
Occasionally, the AES decryption will terminate part way through the string. The encryption of "Hello please give me an A" may decrypt to "Hello ple" or "Hello please giv" or something similar. This happens about 1/20 tests (eyeball, not actual statistical analysis), presumably due to casting and moving the AES encrypted data around and generating a terminating character by mistake somewhere.
