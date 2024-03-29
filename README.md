## Recon-007 [V1 Beta]
Recon-007 is a Bug bounty tool to automate the recon process. It uses threading and consists of more than 20 tools that can help you perform the recon with just a single command.

## Mind Map
![alt text](https://github.com/killeroo7/recon-007/blob/master/mindmap/Recon-007%5Bv1%5D%20.png)


## INSTALLATION
```
1)Clone
git clone https://github.com/killeroo7/recon-007/ && cd recon-007 && chmod +x verify_tools.sh recon-007.py printToolSource.sh
ln -s $PWD/recon-007.py /usr/local/bin/recon-007

2)Install Requirements
pip install -r requirements.txt

3)Check if All the tools are installed
./verify_tools.sh

4)To print the source of each tool
./printToolSource.sh

5)Add APIKeys to db/profile.conf
```

## USAGE
```
1)Print Help
recon-007 -h

2)Basic Usage:
recon-007 -u example.com

3)Print Phases
recon-007 -x

4)Resume from specific Phase when program stopped abruptly
recon-007 -u example.com -p [PhaseNum]
```

## Follow
**Twitter** --> [SickurityWizard](https://twitter.com/sickuritywizard)

