# WiFi-Devices-Distance-Calculator

It's a simple python project that sniffs all the networks and make an estimation about distance between the WiFi device and the using sensor with just using RSSI Signal Power and Channel of WiFi Device.

# Dependencies
  1) Python Scapy Lib
  2) Monitor Mode WiFi Card
  3) Python Pandas Lib (For Printing the Output)

* SCAPY

	a) It can installed by using pip:   
    		pip3 install scapy
  
	b) Can cloned the current development version in Github:  
		git clone https://github.com/secdev/scapy.git  
		cd scapy  
		sudo python setup.py install
  	
* PANDAS

	1) It can also be installed by using pip:  
		pip3 install pandas
  
* MONITOR MODE

	1) Let's start by checking for the interface name:  
		sudo iwconfig  
	It shows the name of the interface "wlan0" and that it is in "Mode: Managed".

	2) To enable monitor mode you once again have to turn the interface off, change its mode, then bring it back up again:  
		sudo ifconfig wlan0 down  
		sudo iwconfig wlan0 mode monitor  
		sudo ifconfig wlan0 up  
	Check that with the "iwconfig" that the mode is changed to Monitor.

	3) To return the interface to normal managed mode:  
		sudo ifconfig wlan0 down  
		sudo iwconfig wlan0 mode managed  
		sudo ifconfig wlan0 up  
  
# Distance Calculation
  
By scanning a Wi-Fi traffic, your antenna will receive different signal power levels from different hosts, measured in dBm (decibel-meter). This power level can be converted into an approximate distance using some math based on the signal's frequency.  
The basic idea is the more strong the signal, the closer you're to the host and vice versa.  
Although the position of an electron can't be determined and neither its energy, this can be mathematically formalized using Free-space path loss logarithmic attenuation :


<p align="center">

  <img src="https://user-images.githubusercontent.com/56837694/130411957-49c0b2a8-3e7f-498e-958b-aeed37665e27.png">

</p>


147.55 is the constant which depends on the units, in this case it will be megahertz and meters, with the associated constant equal to 27.55.  
If distance is to be calculated, the formula needs to be reversed as follows: 

<p align="center">

  <img src="https://user-images.githubusercontent.com/56837694/130411977-644661da-b291-454c-91ee-a6b3aca36df2.png">

</p>


1) f is the frequency of WiFi in MHz
2) dBm is the indicated power level (RSSI Signal Strength)
3) c is our FSPL constant (27.55)
