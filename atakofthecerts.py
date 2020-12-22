#!/usr/bin/python
from OpenSSL import crypto
import os
import getopt
import sys
import random
from shutil import copyfile


class AtakOfTheCerts:
    def __init__(self, pwd="atakatak"):
        self.key = crypto.PKey()
        self.CERTPWD = pwd
        self.cakeypath = f"./ca.key"
        self.cacrtpath = f"./ca.crt"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return None

    def generate_ca(self):
        if not os.path.exists(aotc.cakeypath):
            print("Cannot find CA locally so generating one")
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
            cert.sign(ca_key, "sha256")

            f = open(self.cakeypath, "wb")
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
            f.close()
            print("CA key Stored Here: " + self.cakeypath)

            f = open(self.cacrtpath, "wb")
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            f.close()
            print("CA crt Stored Here: " + self.cacrtpath)
        else:
            print("CA found locally, not generating a new one")

    def generate_key(self, keypath):
        if os.path.exists(keypath):
            print("Certificate file exists, aborting.")
            print(keypath)
            sys.exit(1)
        else:
            print("Generating Key...")
            self.key.generate_key(crypto.TYPE_RSA, 2048)
            f = open(keypath, "wb")
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self.key))
            f.close()
            print("Key Stored Here: " + keypath)

    def generate_certificate(self, cn, crtpath, p12path):
        cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.cakeypath).read())
        cacrt = crypto.load_certificate(crypto.FILETYPE_PEM, open(self.cacrtpath, 'rb').read())
        serialnumber = random.getrandbits(64)
        chain = (cacrt,)
        cert = crypto.X509()
        cert.get_subject().CN = cn
        cert.set_serial_number(serialnumber)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(315360000)
        cert.set_issuer(cacrt.get_subject())
        cert.set_pubkey(self.key)
        cert.set_version(2)
        cert.sign(cakey, "sha256")
        p12 = crypto.PKCS12()
        p12.set_privatekey(self.key)
        p12.set_certificate(cert)
        p12.set_ca_certificates(tuple(chain))
        p12data = p12.export(passphrase=bytes(self.CERTPWD, encoding='UTF-8'))
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

    def bake(self, cn):
        keypath = f"./{cn}.key"
        crtpath = f"./{cn}.crt"
        p12path = f"./{cn}.p12"
        self.generate_key(keypath)
        self.generate_certificate(cn, crtpath, p12path)

    def generate_auto_certs(self, copy=False):
        cns = ["pubserver", "user"]
        for cn in cns:
            self.bake(cn)
        if copy:
            python37_fts_path = "/usr/local/lib/python3.7/dist-packages/FreeTAKServer"
            python38_fts_path = "/usr/local/lib/python3.8/dist-packages/FreeTAKServer"
            if os.path.exists(python37_fts_path):
                dest = python37_fts_path
            elif os.path.exists(python38_fts_path):
                dest = python38_fts_path
            else:
                print("Cannot Find FreeTAKServer install location, cannot copy")
                return False
            if not os.path.exists(dest + "/Certs"):
                os.makedirs(dest + "/Certs")
            print("Copying ./pubserver.key to :" + dest + "/Certs" + "/pubserver.key")
            copyfile("./pubserver.key", dest + "/Certs" + "/pubserver.key")
            print("Done")
            print("Copying ./pubserver.key to :" + dest + "/Certs" + "/pubserver.key.unencrypted")
            copyfile("./pubserver.key", dest + "/Certs" + "/pubserver.key.unencrypted")
            print("Done")
            print("Copying ./pubserver.crt to :" + dest + "/Certs" + "/pubserver.pem")
            copyfile("./pubserver.crt", dest + "/Certs" + "/pubserver.pem")
            print("Done")
            print("Copying ./ca.crt to :" + dest + "/Certs" + "/ca.pem")
            copyfile("./ca.crt", dest + "/Certs" + "/ca.pem")
            print("Done")


if __name__ == '__main__':
    VERSION = "0.3.2"
    help_txt = "This Python script is to be used to generate the certificate files needed for \n" \
               "FTS Version 1.3 and above to allow for SSL/TLS connections between Server and \n" \
               "Client.\n\n" \
               "This script works in the current working directory (the folder you are \n" \
               "currently in)\n\n" \
               "The .p12 files generated will need to be copied to ATAK clients\n" \
               "the default password set on the .p12 files is atakatak\n" \
               "The Server .key and .crt file will ne needed on the FTS server as per the MainConfig.py\n" \
               "The ca.crt is also needed for the MainConfig.py\n" \
               "the default password set on the .p12 files is atakatak, this can be overridden\n\n" \
               "Arguments:\n" \
               "-h --help : to open help\n" \
               "-v --version : to print the version number of the script\n" \
               "-p --password : to change the password for the p12 files from the default atakatak\n" \
               "-a --automated : to run the script in a headless mode to auto generate ca,server and user certs " \
               "for a fresh install\n" \
               "-c --copy : Use this in conjunction with -a to copy the server certs needed into the default location for FTS\n\n"
    AUTO = False
    COPY = False
    CERTPWD = "atakatak"
    cmd_args = sys.argv
    arg_list = cmd_args[1:]
    stort_opts = "avhcp:"
    long_opts = ["automated", "version", "help", "copy", "password"]
    args, values = getopt.getopt(arg_list, stort_opts, long_opts)
    for current_arg, current_val in args:
        if current_arg in ("-h", "--help"):
            print(help_txt)
        if current_arg in ("-v", "--version"):
            print(VERSION)
            exit(1)
        if current_arg in ("-p", "--password"):
            CERTPWD = current_val
        if current_arg in ("-a", "--automated"):
            AUTO = True
        if current_arg in ("-c", "--copy"):
            COPY = True

    with AtakOfTheCerts() as aotc:
        aotc.generate_ca()
    if AUTO:
        with AtakOfTheCerts() as aotc:
            aotc.generate_auto_certs(COPY)
    else:
        while True:
            with AtakOfTheCerts(CERTPWD) as aotc:
                cn = input("Enter the DNS Name or IP of FTS or Username for User Cert: ")
                aotc.bake(cn)
                cont = input("Generate another? y/n")
                if cont.lower() != "y":
                    break
