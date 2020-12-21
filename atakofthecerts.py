#!/usr/bin/python
from OpenSSL import crypto
import os
import getopt
import sys
import random

VERSION = 0.3
HOME = "."
help_txt = "This Python script is to be used to generate the certificate files needed for \n" \
           "FTS Version 1.3 and above to allow for SSL/TLS connections between Server and \n" \
           "Client.\n\n" \
           "This script works in the current working directory (the folder you are \n" \
           "currently in)\n\n"\
           "The .p12 files generated will need to be copied to ATAK clients\n" \
           "the default password set on the .p12 files is atakatak\n" \
           "The Server .key and .crt file will ne needed on the FTS server as per the MainConfig.py\n" \
           "The ca.crt is also needed for the MainConfig.py\n"\
           "the default password set on the .p12 files is atakatak, this can be overridden\n\n" \
           "Arguments:\n" \
           "-h --help : to open help\n" \
           "-v --version : to print the version number of the script\n" \
           "-p --password : to change the password for the p12 files from the default atakatak\n" \
           "-a --automated : to run the script in a headless mode to auto generate ca,server and user certs " \
           "for a fresh install\n\n"
key = crypto.PKey()
CERTPWD = "atakatak"
AUTO = False
cmd_args = sys.argv
arg_list = cmd_args[1:]
stort_opts = "avhp:"
long_opts = ["automated", "version", "help", "password"]
args, values = getopt.getopt(arg_list, stort_opts, long_opts)
for current_arg, current_val in args:
    if current_arg in ("-h", "--help"):
        print(help_txt)
    if current_arg in ("-v", "--version"):
        print(VERSION)
    if current_arg in ("-p", "--password"):
        CERTPWD = current_val
    if current_arg in ("-a", "--automated"):
        AUTO = True


cakeypath = f"{HOME}/ca.key"
cacrtpath = f"{HOME}/ca.crt"


def generate_ca():
    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().CN = "CA"
    cert.set_serial_number(0)
    cert.set_version(2)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)
    cert.set_issuer(cert.get_subject())
    cert.add_extensions([crypto.X509Extension(b'basicConstraints', False, b'CA:TRUE'), crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign')])
    cert.set_pubkey(ca_key)
    cert.sign(ca_key, 'sha256')

    f = open(cakeypath, "wb")
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
    f.close()
    print("CA key Stored Here: " + cakeypath)

    f = open(cacrtpath, "wb")
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    f.close()
    print("CA crt Stored Here: " + cacrtpath)


def generate_key(keypath):
    if os.path.exists(keypath):
        print("Certificate file exists, aborting.")
        print(keypath)
        sys.exit(1)
    else:
        print("Generating Key...")
        key.generate_key(crypto.TYPE_RSA, 2048)
        f = open(keypath, "wb")
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        f.close()
        print("Key Stored Here: " + keypath)


def generate_certificate(cn, crtpath, p12path):
    cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, open(cakeypath).read())
    cacrt = crypto.load_certificate(crypto.FILETYPE_PEM, open(cacrtpath, 'rb').read())
    serialnumber = random.getrandbits(64)
    chain = (cacrt,)
    cert = crypto.X509()
    cert.get_subject().CN = cn
    cert.set_serial_number(serialnumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(315360000)
    cert.set_issuer(cacrt.get_subject())
    cert.set_pubkey(key)
    cert.set_version(2)
    cert.sign(cakey, "sha256")
    p12 = crypto.PKCS12()
    p12.set_privatekey(key)
    p12.set_certificate(cert)
    p12.set_ca_certificates(tuple(chain))
    p12data = p12.export(passphrase=bytes(CERTPWD, encoding='UTF-8'))
    with open(p12path, 'wb') as p12file:
        p12file.write(p12data)
        print("P12 Stored Here: " + p12path)

    if os.path.exists(crtpath):
        print("Certificate File Exists, aborting.")
        print(crtpath)
    else:
        f = open(crtpath, "wb")
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        f.close()
        print("CRT Stored Here: " + crtpath)


def bake(cn):
    keypath = f"{HOME}/{cn}.key"
    crtpath = f"{HOME}/{cn}.crt"
    p12path = f"{HOME}/{cn}.p12"
    generate_key(keypath)
    generate_certificate(cn, crtpath, p12path)


if __name__ == '__main__':
    if not os.path.exists(cakeypath):
        print("Cannot find CA locally so generating one")
        generate_ca()
    if AUTO:
        cns = ["pubserver", "user"]
        for cn in cns:
            bake(cn)
    else:
        while True:
            cn = input("Enter the DNS Name or IP of FTS or Username for User Cert: ")
            bake(cn)
            cont = input("Generate another? y/n")
            if cont.lower() != "y":
                break








