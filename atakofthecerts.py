# !/usr/bin/python
import subprocess

try:
    from OpenSSL import crypto
except ImportError:
    subprocess.run(["pip3", "install", "pyopenssl"], capture_output=True)
    from OpenSSL import crypto
import getopt
import sys
import os
import random
from shutil import copyfile
import uuid

try:
    from jinja2 import Template
except ImportError:
    subprocess.run(["pip3", "install", "jinja2"], capture_output=True)
    from jinja2 import Template
import socket
import zipfile
import shutil

try:
    import requests
except ImportError:
    subprocess.run(["pip3", "install", "requests"], capture_output=True)
import hashlib


def _utc_time_from_datetime(date):
    fmt = '%y%m%d%H%M'
    if date.second > 0:
        fmt += '%S'
    if date.tzinfo is None:
        fmt += 'Z'
    else:
        fmt += '%z'
    return date.strftime(fmt)


def revoke_certificate(ca_pem, ca_key, revoked_file, crl_file, user_cert_dir, username, crl_path=None):
    """
    Function to create/update a CRL with revoked user certificates
    :param ca_pem: The path to your CA PEM file
    :param ca_key: The Path to your CA key file
    :param revoked_file: Path to JSON file to be used as a DB for revocation
    :param crl_file: Path to CRL file
    :param user_cert_dir: Path to director containing all issued user PEM files
    :param username: the username to Revoke
    :param crl_path: The path to your previous CRL file to be loaded and updated
    :return: bool
    """

    import os
    import json
    from OpenSSL import crypto
    from datetime import datetime
    data = {}
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, open(ca_pem, mode="rb").read())
    private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(ca_key, mode="r").read())
    if crl_path:
        crl = crypto.load_crl(crypto.FILETYPE_PEM, open(crl_path, mode="rb").read())
    else:
        crl = crypto.CRL()
        if os.path.exists(revoked_file):
            with open(revoked_file, 'r') as json_file:
                data = json.load(json_file)

    for cert in os.listdir(user_cert_dir):
        if cert.lower() == f"{username.lower()}.pem":
            with open(cert, 'rb') as cert:
                revoked_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert.read())
            data[str(revoked_cert.get_serial_number())] = username
            break

    for key in data:
        revoked_time = _utc_time_from_datetime(datetime.utcnow())
        revoked = crypto.Revoked()
        revoked.set_serial(format(int(key), "02x").encode())
        revoked.set_rev_date(bytes(revoked_time, encoding='utf8'))
        crl.add_revoked(revoked)
    crl.sign(certificate, private_key, b"sha256")

    with open(revoked_file, 'w+') as json_file:
        json.dump(data, json_file)

    with open(crl_file, 'wb') as f:
        f.write(crl.export(cert=certificate, key=private_key, digest=b"sha256"))

    delete = 0
    with open(ca_pem, "r") as f:
        lines = f.readlines()
    with open(ca_pem, "w") as f:
        for line in lines:
            if delete:
                continue
            elif line.strip("\n") != "-----BEGIN X509 CRL-----":
                f.write(line)
            else:
                delete = 1

    with open(ca_pem, "ab") as f:
        f.write(crl.export(cert=certificate, key=private_key, digest=b"sha256"))


def send_data_package(server: str, dp_name: str = "user.zip") -> bool:
    """
    Function to send data package to server
    :param server: Server address where the package will be uploaded
    :param dp_name: Name of the zip file to upload
    :return: bool
    """
    file_hash = hashlib.sha256()
    block_size = 65536
    with open(dp_name, 'rb') as f:
        fb = f.read(block_size)
        while len(fb) > 0:
            file_hash.update(fb)
            fb = f.read(block_size)

    with open(dp_name, 'rb') as f:
        s = requests.Session()
        r = s.post(f'http://{server}:8080/Marti/sync/missionupload?hash={file_hash.hexdigest()}'
                   f'&filename={dp_name}'
                   f'&creatorUid=atakofthecerts',
                   files={"assetfile": f.read()},
                   headers={'Expect': '100-continue'})
        if r.status_code == 200:
            p_r = s.put(f'http://{server}:8080/Marti/api/sync/metadata/{file_hash.hexdigest()}/tool')
            return True
        else:
            print("Something went wrong uploading DataPackage!")
            return False


def generate_zip(server_address: str = None, server_filename: str = "pubserver.p12", user_filename: str = "user.p12",
                 cert_password: str = "atakatak", ssl_port: str = "8089") -> None:
    """
    A Function to generate a Client connection Data Package (DP) from a server and user p12 file in the current
    working directory.
    :param server_address: A string based ip address or FQDN that clients will use to connect to the server
    :param server_filename: The filename of the server p12 file default is pubserver.p12
    :param user_filename: The filename of the server p12 file default is user.p12
    :param cert_password: The password for the certificate files
    :param ssl_port: The port used for SSL CoT, defaults to 8089
    """
    pref_file_template = Template("""<?xml version='1.0' standalone='yes'?>
    <preferences>
        <preference version="1" name="cot_streams">
            <entry key="count" class="class java.lang.Integer">1</entry>
            <entry key="description0" class="class java.lang.String">FreeTAKServer_{{ server }}</entry>
            <entry key="enabled0" class="class java.lang.Boolean">true</entry>
            <entry key="connectString0" class="class java.lang.String">{{ server }}:{{ ssl_port }}:ssl</entry>
        </preference>
        <preference version="1" name="com.atakmap.app_preferences">
            <entry key="displayServerConnectionWidget" class="class java.lang.Boolean">true</entry>
            <entry key="caLocation" class="class java.lang.String">/storage/emulated/0/atak/cert/{{ server_filename }}</entry>
            <entry key="caPassword" class="class java.lang.String">{{ cert_password }}</entry>
            <entry key="clientPassword" class="class java.lang.String">{{ cert_password }}</entry>
            <entry key="certificateLocation" class="class java.lang.String">/storage/emulated/0/atak/cert/{{ user_filename }}</entry>
        </preference>
    </preferences>
    """)

    manifest_file_template = Template("""<MissionPackageManifest version="2">
       <Configuration>
          <Parameter name="uid" value="{{ uid }}"/>
          <Parameter name="name" value="FreeTAKServer_{{ server }}"/>
          <Parameter name="onReceiveDelete" value="true"/>
       </Configuration>
       <Contents>
          <Content ignore="false" zipEntry="{{ folder }}/fts.pref"/>
          <Content ignore="false" zipEntry="{{ folder }}/{{ server_filename }}"/>
          <Content ignore="false" zipEntry="{{ folder }}/{{ user_filename }}"/>	  
       </Contents>
    </MissionPackageManifest>
    """)

    manifest_file_parent_template = Template("""<MissionPackageManifest version="2">
           <Configuration>
              <Parameter name="uid" value="{{ uid }}"/>
              <Parameter name="name" value="FreeTAKServer_{{ server }}_DP"/>
           </Configuration>
           <Contents>
              <Content ignore="false" zipEntry="{{ folder }}/{{ internal_dp_name }}.zip"/>
           </Contents>
        </MissionPackageManifest>
        """)
    username = user_filename[:-4]
    random_id = uuid.uuid4()
    new_uid = uuid.uuid4()
    parent_folder = "80b828699e074a239066d454a76284eb"
    folder = "5c2bfcae3d98c9f4d262172df99ebac5"
    if server_address is None:
        hostname = socket.gethostname()
        server_address = socket.gethostbyname(hostname)
    pref = pref_file_template.render(server=server_address, server_filename=server_filename.replace("./", ""),
                                     user_filename=user_filename.replace("./", ""), cert_password=cert_password,
                                     ssl_port=ssl_port)
    man = manifest_file_template.render(uid=random_id, server=server_address,
                                        server_filename=server_filename.replace("./", ""),
                                        user_filename=user_filename.replace("./", ""), folder=folder)
    man_parent = manifest_file_parent_template.render(uid=new_uid, server=server_address,
                                                      folder=parent_folder,
                                                      internal_dp_name=f"{username.replace('./', '')}")
    if not os.path.exists(f"./{folder}"):
        os.makedirs(f"./{folder}")
    if not os.path.exists("./MANIFEST"):
        os.makedirs("./MANIFEST")
    with open(f'./{folder}/fts.pref', 'w') as pref_file:
        pref_file.write(pref)
    with open('./MANIFEST/manifest.xml', 'w') as manifest_file:
        manifest_file.write(man)
    print(f"Generating inner Data Package: {username}.zip")
    copyfile(f"./{server_filename}", f"./{folder}/{server_filename}")
    copyfile(f"./{user_filename}", f"./{folder}/{user_filename}")
    zipf = zipfile.ZipFile(f"{username}.zip", 'w', zipfile.ZIP_DEFLATED)
    for root, dirs, files in os.walk('./' + folder):
        for file in files:
            zipf.write(os.path.join(root, file))
    for root, dirs, files in os.walk('./MANIFEST'):
        for file in files:
            zipf.write(os.path.join(root, file))
    zipf.close()
    shutil.rmtree("./MANIFEST")
    shutil.rmtree("./" + folder)
    # Create outer DP...because WinTAK
    if not os.path.exists("./" + parent_folder):
        os.makedirs("./" + parent_folder)
    if not os.path.exists("./MANIFEST"):
        os.makedirs("./MANIFEST")
    with open('./MANIFEST/manifest.xml', 'w') as manifest_parent:
        manifest_parent.write(man_parent)
    print(f"Generating Main Data Package: {username}_DP.zip")
    copyfile(f"./{username}.zip", f"./{parent_folder}/{username}.zip")
    zipp = zipfile.ZipFile(f"{username}_DP.zip", 'w', zipfile.ZIP_DEFLATED)
    for root, dirs, files in os.walk('./' + parent_folder):
        for file in files:
            zipp.write(os.path.join(root, file))
    for root, dirs, files in os.walk('./MANIFEST'):
        for file in files:
            zipp.write(os.path.join(root, file))
    zipp.close()
    shutil.rmtree("./MANIFEST")
    shutil.rmtree("./" + parent_folder)
    os.remove(f"./{username}.zip")


class AtakOfTheCerts:
    def __init__(self, pwd: str = "atakatak") -> None:
        """
        :param pwd: String based password used to secure the p12 files generated, defaults to atakatak
        """
        self.key = crypto.PKey()
        self.cert_pwd = pwd
        self.ca_key_path = "./ca.key"
        self.ca_pem_path = "./ca.pem"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return None

    def generate_ca(self, expiry_time_secs: int = 31536000) -> None:
        """
        Generate a CA certificate
        """
        if not os.path.exists(self.ca_key_path):
            print("Cannot find CA locally so generating one")
            ca_key = crypto.PKey()
            ca_key.generate_key(crypto.TYPE_RSA, 2048)
            cert = crypto.X509()
            cert.get_subject().CN = "CA"
            cert.set_serial_number(0)
            cert.set_version(2)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(expiry_time_secs)
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(ca_key)
            cert.sign(ca_key, "sha256")

            f = open(self.ca_key_path, "wb")
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
            f.close()
            print(f"CA key Stored Here: {self.ca_key_path}")

            f = open(self.ca_pem_path, "wb")
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            f.close()
            print(f"CA pem Stored Here: {self.ca_pem_path}")
        else:
            print("CA found locally, not generating a new one")

    def _generate_key(self, key_path: str) -> None:
        """
        Generate a new certificate key
        :param key_path: String based filepath to place new key, this should have a .key file extension
        """
        if os.path.exists(key_path):
            print("Certificate file exists, aborting.")
            print(key_path)
            sys.exit(1)
        else:
            print("Generating Key...")
            self.key.generate_key(crypto.TYPE_RSA, 2048)
            f = open(key_path, "wb")
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self.key))
            f.close()
            print(f"Key Stored Here: {key_path}")

    def _generate_certificate(self, common_name: str, pem_path: str, p12path: str,
                              expiry_time_secs: int = 31536000) -> None:
        """
        Create a certificate and p12 file
        :param common_name: Common Name for certificate
        :param pem_path: String filepath for the pem file created
        :param p12path: String filepath for the p12 file created
        :param expiry_time_secs: length of time in seconds that the certificate is valid for, defaults to 1 year
        """
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.ca_key_path).read())
        ca_pem = crypto.load_certificate(crypto.FILETYPE_PEM, open(self.ca_pem_path, 'rb').read())
        serial_number = random.getrandbits(64)
        chain = (ca_pem,)
        cert = crypto.X509()
        cert.get_subject().CN = common_name
        cert.set_serial_number(serial_number)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(expiry_time_secs)
        cert.set_issuer(ca_pem.get_subject())
        cert.set_pubkey(self.key)
        cert.set_version(2)
        cert.sign(ca_key, "sha256")
        cert.add_extensions([
                             crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
                             ])
        p12 = crypto.PKCS12()
        p12.set_privatekey(self.key)
        p12.set_certificate(cert)
        p12.set_ca_certificates(tuple(chain))
        p12data = p12.export(passphrase=bytes(self.cert_pwd, encoding='UTF-8'))
        with open(p12path, 'wb') as p12file:
            p12file.write(p12data)
            print("P12 Stored Here: " + p12path)

        if os.path.exists(pem_path):
            print("Certificate File Exists, aborting.")
            print(pem_path)
        else:
            f = open(pem_path, "wb")
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            f.close()
            print(f"PEM Stored Here: {pem_path}")

    def bake(self, common_name: str, cert: str = "user", expiry_time_secs: int = 31536000) -> None:
        """
        Wrapper for creating certificate and all files needed
        :param common_name: Common Name of the the certificate
        :param cert: Type of cert being created "user" or "server"
        :param expiry_time_secs: length of time in seconds that the certificate is valid for, defaults to 1 year
        """
        keypath = f"./{common_name}.key"
        pempath = f"./{common_name}.pem"
        p12path = f"./{common_name}.p12"
        self._generate_key(keypath)
        self._generate_certificate(common_name, pempath, p12path, expiry_time_secs)
        if cert.lower() == "server":
            copyfile(keypath, keypath + ".unencrypted")

    @staticmethod
    def copy_server_certs(server_name: str = "pubserver") -> None:
        """
        copy all the server files with of a given name to the FTS server cert location
        :param server_name: Name of the server/IP address that was used when generating the certificate
        """
        try:
            import FreeTAKServer.controllers.configuration.MainConfig as Mainconfig
        except ImportError:
            print("Cannot import FTS, it must not be installed on this machine. cannot continue")
            exit(0)
        # if not os.path.exists(Mainconfig.MainConfig.certsPath):
        #     os.makedirs(Mainconfig.MainConfig.certsPath)
        print(f"Copying ./{server_name}.key to : {Mainconfig.MainConfig.keyDir}")
        copyfile(f"./{server_name}.key", Mainconfig.MainConfig.keyDir)
        print("Done")
        print(f"Copying ./{server_name}.key to : {Mainconfig.MainConfig.unencryptedKey}")
        copyfile(f"./{server_name}.key", Mainconfig.MainConfig.unencryptedKey)
        print("Done")
        print(f"Copying ./{server_name}.pem to : {Mainconfig.MainConfig.pemDir}")
        copyfile(f"./{server_name}.pem", Mainconfig.MainConfig.pemDir)
        print("Done")
        print(f"Copying ./{server_name}.p12 to : {Mainconfig.MainConfig.p12Dir}")
        copyfile(f"./{server_name}.p12", Mainconfig.MainConfig.p12Dir)
        print("Done")
        print(f"Copying ./ca.pem to : {Mainconfig.MainConfig.CA}")
        copyfile("./ca.pem", Mainconfig.MainConfig.CA)
        print("Done")
        print(f"Copying ./ca.key to : {Mainconfig.MainConfig.CAkey}")
        copyfile("./ca.key", Mainconfig.MainConfig.CAkey)
        print("Done")

    def generate_auto_certs(self, ip: str, copy: bool = False, expiry_time_secs: int = 31536000) -> None:
        """
        Generate the basic files needed for a new install of FTS
        :param ip: A string based ip address or FQDN that clients will use to connect to the server
        :param copy: Whether to copy server files to FTS expected locations
        :param expiry_time_secs: length of time in seconds that the certificate is valid for, defaults to 1 year
        """
        self.bake("pubserver", "server", expiry_time_secs)
        self.bake("user", "user", expiry_time_secs)
        if copy is True:
            self.copy_server_certs()
        generate_zip(server_address=ip)
        send_data_package(server=ip, dp_name='user_DP.zip')


if __name__ == '__main__':
    VERSION = "0.6.5"
    help_txt = "This Python script is to be used to generate the certificate files needed for \n" \
               "FTS Version 1.3 and above to allow for SSL/TLS connections between Server and \n" \
               "Client.\n\n" \
               "This script works in the current working directory (the folder you are \n" \
               "currently in)\n\n" \
               "The .p12 files generated will need to be copied to ATAK clients\n" \
               "the default password set on the .p12 files is atakatak\n" \
               "The Server .key and .pem file will ne needed on the FTS server as per the MainConfig.py\n" \
               "The ca.pem is also needed for the MainConfig.py\n" \
               "the default password set on the .p12 files is atakatak, this can be overridden\n\n" \
               "Arguments:\n" \
               "-h --help : to open help\n" \
               "-v --version : to print the version number of the script\n" \
               "-p --password : to change the password for the p12 files from the default atakatak\n" \
               "-a --automated : to run the script in a headless mode to auto generate ca,server and user certs " \
               "for a fresh install\n" \
               "-c --copy : Use this in conjunction with -a to copy the server certs needed into the " \
               "default location for FTS\n" \
               "-i --ip : The IP address of the server that clients will be accessing it on\n\n"
    AUTO = False
    COPY = False
    IP = False
    CERTPWD = "atakatak"
    cmd_args = sys.argv
    arg_list = cmd_args[1:]
    stort_opts = "avhci:p:"
    long_opts = ["automated", "version", "help", "copy", "ip", "password"]
    args, values = getopt.getopt(arg_list, stort_opts, long_opts)
    for current_arg, current_val in args:
        if current_arg in ("-h", "--help"):
            print(help_txt)
            exit(1)
        if current_arg in ("-v", "--version"):
            print(VERSION)
            exit(1)
        if current_arg in ("-p", "--password"):
            CERTPWD = current_val
        if current_arg in ("-a", "--automated"):
            AUTO = True
        if current_arg in ("-c", "--copy"):
            COPY = True
        if current_arg in ("-i", "--ip"):
            IP = current_val

    with AtakOfTheCerts() as aotc:
        aotc.generate_ca()
    if AUTO:
        if IP is False:
            IP = str(input("Enter IP address or FQDN that clients will use to connect to FTS: "))
        with AtakOfTheCerts() as aotc:
            aotc.generate_auto_certs(copy=COPY, ip=IP)
    else:
        server_p12 = None
        users_p12 = []
        server_question = input("Would you like to generate a server certificate? y/n ")
        if server_question.lower() == "y":
            with AtakOfTheCerts(CERTPWD) as aotc:
                IP = str(input("Enter IP address or FQDN that clients will use to connect to FTS: "))
                aotc.bake(common_name=IP, cert="server")
                server_p12 = f"./{IP}.p12"
            copy_question = input("Would you like to copy the server certificate files where needed for FTS? y/n ")
            if copy_question.lower() == "y":
                aotc.copy_server_certs(server_name=IP)
        user_question = input("Would you like to generate a user certificate? y/n ")
        if user_question.lower() == "y":
            while True:
                with AtakOfTheCerts(CERTPWD) as aotc:
                    cn = input("Username: ")
                    if len(cn) == 0:
                        break
                    aotc.bake(cn, cert="user")
                    users_p12.append(f"./{cn}.p12")
                    cont = input("Generate another? y/n ")
                    if cont.lower() != "y":
                        break
            generate_zip_question = input("Would you like to generate Data Packages for each user just created? y/n ")
            if generate_zip_question.lower() == "y":
                while server_p12 is None:
                    server_p12 = input("Enter path to server p12 file e.g ./pubserver.p12 : ")
                while IP is False:
                    IP = str(input("Enter IP address or FQDN that clients will use to connect to FTS: "))
                for user in users_p12:
                    generate_zip(server_address=IP, server_filename=server_p12, user_filename=user)
                    send_zip_question = input("Would you like to upload the Data Packages? y/n ")
                    username = user.replace('./', '')
                    username = username.replace('.p12', '')
                    if send_zip_question.lower() == "y":
                        send_data_package(server=IP, dp_name=username + '_DP.zip')