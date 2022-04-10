# ATAK-Certs
## This Tool has now been integrated into Taky and FTS so you shouldn't need to run it separately 

Tool for creating Certificate files and Client Data Packages for [Taky](https://github.com/tkuester/taky), [OpenTakRouter](https://github.com/darkplusplus/opentakrouter) and [FTS](https://github.com/FreeTAKTeam/FreeTakServer)

### Command-Line Arguments
`-h` `--help` : to open help

`-v` `--version` : to print the version number of the script

`-p` `--password` : to change the password for the p12 files from the default atakatak

`-a` `--automated` : to run the script in a headless mode to auto generate ca,server and user certs for a fresh install

`-c` `--copy` : Use this in conjunction with `-a` to copy the server certs needed into the default location for FTS only, 
if this is used skip step 5 in How to

`-i` `--ip` : The IP address of the server that clients will be accessing it on

## How To
### Step 1:
Connect you your server instance via SSH, For this I suggest using MobaXterm found here https://mobaxterm.mobatek.net/ This
is great because it opens an SFTP session to the server too needed for copying files from the server.

### Step 2:
Run script in either Headless or Interactive mode:

-**Headless** (recommended for a new install of FTS, change the ip address for the address clients will use to connect, skip step 5 if you use this option):

`curl -L https://git.io/JL9DP | sudo python3 - -a -c -i 192.168.1.100`

-**Interactive** (useful if you need to add more certs to en existing setup)

`curl -L https://git.io/JL9DP | sudo python3 -`

If you run the script interactive, just follow the prompts

### Step 3:
Copy the server and client p12 files, or the Data package zip file from the server to TAK devices, These can be easily dragged a dropped 
from the SFTP session on the left side of MobaXterm 

### Step 4:
###### Skip if you ran the script in headless mode or you answered "y" to "Would you like to copy the server certificate files where needed for FTS?"

Update the MainConfig.py file to point at the certificates just generated in the directory you were in when running step 3

keyDir = The pubserver.key file or whatever you named your sever

pemDir = The pubserver.crt file or whatever you named your sever

unencryptedKey = The pubserver.key file or whatever you named your sever

CA = The ca.crt file

Password = default password for this is atakatak but if you changed the password with the -p flag, use that password
