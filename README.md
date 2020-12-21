# ATAK-Certs
Tool for creating Certificate files for FTS and TAKserver

`-h` `--help` : to open help

`-v` `--version` : to print the version number of the script

`-p` `--password` : to change the password for the p12 files from the default atakatak

`-a` `--automated` : to run the script in a headless mode to auto generate ca,server and user certs for a fresh install


**How To:**

**Step 1:**
Connect you your FTS instance via SSH, For this I suggest using MobaXterm found here https://mobaxterm.mobatek.net/ This
is great because it opens an SFTP session to the server too needed for copying files from the server.

**Step 2:**
Download the latest zip from GitHub

`wget -c https://github.com/lennisthemenace/ATAK-Certs/archive/0.3.1.tar.gz -O - | tar -xz`

**Step 3:**
Change directory to the one just downloaded

`cd ./ATAK-Certs-0.3`

**Step 4:**
Run the script

Headless (recommended for a new install of FTS):

`python3 ./atakofthecerts.py -a`

Interactive (useful if you need to add more certs to en existing setup)

`python3 ./atakofthecerts.py`

If you run the script interactive, just follow the prompts

**Step 5:**
Copy the server and client p12 files from the server to TAK devices, These can be easily dragged a dropped 
from the SFTP session on the left side of MobaXterm 

**Step 6:**
Update the MainConfig.py file to point at the certificates just generated in ~/ATAK-Certs-0.3.1

keyDir = The pubserver.key file or whatever you named your sever

pemDir = The pubserver.crt file or whatever you named your sever

unencryptedKey = The pubserver.key file or whatever you named your sever

CA = The ca.crt file

Password = default password for this is atakatak but if you changed the password with the -p flag, use that password