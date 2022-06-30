#!/usr/bin/env sh 

NC='\033[0m' #No Color
RED='\033[0;31m'
CYAN='\033[1;34m'
PURPLE='\033[0;35m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'

printSource(){
   # echo ${YELLOW}"[-] $1 --> $2"${NC}
   printf "${GREEN}%-20s ${NC} --> ${YELLOW}%s \n${NC}" "$1" "$2"

}



printSource "sublist3r.py" "https://github.com/aboul3la/Sublist3r";
printSource "assetfinder" "https://github.com/tomnomnom/assetfinder";
printSource "amass" "https://github.com/OWASP/Amass";
printSource "subfinder" "https://github.com/projectdiscovery/subfinder";
printSource "shosubgo_linux" "https://github.com/incogbyte/shosubgo";
printSource "subjs" "https://github.com/lc/subjs";
printSource "httprobe" "https://github.com/tomnomnom/httprobe";
printSource "aquatone" "https://github.com/michenriksen/aquatone";
printSource "gau" "https://github.com/lc/gau#installation";
printSource "wafw00f" "https://github.com/EnableSecurity/wafw00f";
printSource "spoofcheck.py" "https://github.com/a6avind/spoofcheck";
printSource "masscan" "sudo apt install masscan";
printSource "subjack" "https://github.com/haccer/subjack";
printSource "SubOver" "https://github.com/Ice3man543/SubOver";
printSource "hakrawler" "https://github.com/hakluke/hakrawler";
printSource "aria2c" "sudo apt-get install aria2";
printSource "smashDupes-007" "https://github.com/killeroo7/smashdupes-007";
printSource "github-subdomains.py"  "https://github.com/gwen001/github-search";
printSource "virtual-host-discovery.rb" "https://github.com/jobertabma/virtual-host-discovery";
printSource "waybackrobots.py" "https://gist.github.com/mhmdiaa/2742c5e147d49a804b408bfed3d32d07#file-waybackrobots-py [Add python3 shebang to script and add it to path]";
