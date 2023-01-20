# ReadME

This tool verifies whether an inputted IP address is a hardware device or not. This tool uses criminalip.io's API.



# Criminal IP

Criminal IP is a search engine that finds internet connected devices, evaluates IP addresses and domain links. They have useful filters and tags that narrow down search results efficiently, so it's pretty beginner-friendly.




----------



# Prerequisites

-   [criminalip.io](http://criminalip.io) API Key
    

Get it [here](https://www.criminalip.io/ko)



# Installation

Clone repository:

$ git clone https://github.com/ettoibronx/chercheur_ware.git

$ cd chercheur_ware

$ python3 -m venv .venv 
$ source .venv/bin/activate

$ pip3 install -r requirements.txt



# Getting started

$ python3 chercheur_ware.git.py [Command]



# Optional Arguments (Commands)

| Flag          | Meta_Var      | Usage                                       |
| ------------- | ------------- | ------------------------------------------- |
| `-K/--key`    | **API key**   | python3 hardware_finder.py -K abcdefg...    |
| `-F/--file`   | **File/Path** | python3 hardware_finder.py -F sample.txt    |
| `-I/--ip`     | **IP**        | python3 hardware_finder.py -I 1.1.1.1       |
| `-C/--cidr`   | **cidr**      | python3 hardware_finder.py -I 1.1.1.1 -C 24 |
| `-O/--output` | **File Path** | python3 hardware_finder.py -W log.txt       |

