#!/usr/bin/env sh 

NC='\033[0m' #No Color
RED='\033[0;31m'
CYAN='\033[1;34m'
PURPLE='\033[0;35m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'

echo ${YELLOW}"\n--------------------------------\n\tRECON-007\n--------------------------------\n"${NC}

checktool(){
	if ! [ -x "$(command -v $1)" ]; then
	  echo ${RED}"[-] MISSING --> $1"${NC}
	else
		echo ${CYAN}"[+] FOUND --> $1"${NC}
	fi
}

vhostdiscoverycheck(){
	if ! [ -x "$(command -v virtual-host-discovery.rb)" ]; then
	  echo ${RED}"[-] MISSING --> virtual-host-discovery.rb [Rename scan.rb as virtual-host-discovery.rb and add Shebang to it]"${NC}
	else
		echo ${CYAN}"[+] FOUND --> virtual-host-discovery.rb"${NC}
	fi
}

checktool "sublist3r.py"          #https://github.com/aboul3la/Sublist3r
checktool "assetfinder"           #https://github.com/tomnomnom/assetfinder
checktool "amass"                 #https://github.com/OWASP/Amass
checktool "subfinder"             #https://github.com/projectdiscovery/subfinder
checktool "github-subdomains.py"  #https://github.com/gwen001/github-search
checktool "shosubgo_linux"        #https://github.com/incogbyte/shosubgo
checktool "subjs"                 #https://github.com/lc/subjs
checktool "httprobe"              #https://github.com/tomnomnom/httprobe
checktool "aquatone"              #https://github.com/michenriksen/aquatone
checktool "gau"                   #https://github.com/lc/gau#installation
checktool "waybackrobots.py"      #https://gist.github.com/mhmdiaa/2742c5e147d49a804b408bfed3d32d07#file-waybackrobots-py [Add python3 shebang to script and add it to path]
checktool "wafw00f"               #https://github.com/EnableSecurity/wafw00f
vhostdiscoverycheck               #https://github.com/jobertabma/virtual-host-discovery
checktool "spoofcheck.py"         #https://github.com/a6avind/spoofcheck
checktool "masscan"               #sudo apt install masscan
checktool "subjack"               #https://github.com/haccer/subjack
checktool "SubOver"               #https://github.com/Ice3man543/SubOver
checktool "hakrawler"             #https://github.com/hakluke/hakrawler
checktool "aria2c"                #sudo apt-get install aria2
checktool "smashDupes-007"        #https://github.com/killeroo7/smashdupes-007

echo ${GREEN}"\n[IMP] Install GF tool[https://github.com/tomnomnom/gf] and add patterns by 1ndianl33t [https://github.com/1ndianl33t/Gf-Patterns/]"
echo ${GREEN}"[IMP] Check Manually if GitAllSecrets is installed using the command: sudo docker run -it abhartiya/tools_gitallsecrets"
echo ${GREEN}"[IMP] If the tool is installed and yet it says missing, check if the tool name is matching to yours"
