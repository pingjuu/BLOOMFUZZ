# BLOOMFUZZ
Unveiling Bluetooth L2CAP Vulnerabilities via State Cluster Fuzzing with Target-Oriented State Machines.


## Prerequisites

### version info
python: 3.8.10, scapy: 2.4.4, ouilookup: 0.2.4

```
$sudo apt-get install python3-pip
$sudo pip3 install scapy==2.4.4
$sudo apt-get install libbluetooth-dev
$sudo pip3 install pybluez
$sudo pip3 install ouilookup==0.2.4
```



## Running the fuzzer
### Create log dir in BLOOMFUZZ
```
mkdir log
```
### Normal transition capture to run fuzzer.
```
mkdir CommCapture
```
- Start Bluetooth packet capture with Wireshark.
- Connect the host running the fuzzer to the target device.
- End the capture and save the pcapng file in the CommCapture directory.

### How to run
1. move to BLOOMFUZZ folder.
2. run main.py with sudo.
```
sudo python3 ./main.py -p CommCapture/[filename].pcapng
ex) sudo python3 main.py -p CommCapture/window.pcapng
```
3. Choose target device.
```
Performing classic bluetooth inquiry scan...
nearby devices : 2

	Target Bluetooth Device List
	[No.]	[BT address]		[Device name]		[Device Class]			[OUI]
	00.	AA:BB:CC:DD:EE:FF	Pixel 3		Phone(Smartphone)		Google, Inc.
	01.	FF:EE:DD:CC:BB:AA	pingjuu2	Computer(Desktop workstation)	cyber-blue(HK)Ltd
	Found 2 devices

Choose Device : 0
```
4. Choose target service which is supported by L2CAP.

```
Start scanning services...

	List of profiles for the device
	00. [0x0000]: Service A
	01. [0x0001]: Service B
	02. [0x0002]: Service C
	03. [0x0003]: Service D
	04. [0x0004]: Service E
	05. [0x0005]: Service F
	
Select a profile to fuzz : 2
```
5. Fuzz testing start.

### End test
The fuzzer ends after transmitting 2,000,000 packets. If you want to quit before then, type Ctrl+C.
```
Ctrl + C
```

### Log file

The log file will be generated after the fuzz testing in Bloom/log folder.

## Paper
Contacts : pingjuu@korea.ac.kr, https://ccs.korea.ac.kr/
