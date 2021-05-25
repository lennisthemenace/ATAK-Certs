import atakofthecerts

# Generate initial certs and copy the serve certs to the correct directory
# This is the same as running "sudo python3 atackofthecerts.py -a -c -i 192.168.1.100"
with atakofthecerts.AtakOfTheCerts() as aotc:
    aotc.generate_ca()
    aotc.generate_auto_certs(ip="192.168.1.100", copy=True)

# Generate a server certificate for a server at 192.168.1.100, a user certificate for the username test_user
# then generates a zip based ATAK data package for client connection
with atakofthecerts.AtakOfTheCerts() as aotc:
    aotc.generate_ca(expiry_time_secs=31536000)
    aotc.bake(common_name="192.168.1.100", cert="server", expiry_time_secs=31536000)
    aotc.bake(common_name="user", cert="user", expiry_time_secs=31536000)
atakofthecerts.generate_zip(server_address="192.168.1.100", server_filename="192.168.1.100.p12", user_filename="user.p12",
                            ssl_port="8089")


# Revoke Certificates and generate/update a CRL

atakofthecerts.revoke_certificate(ca_pem='./ca.pem', ca_key='./ca.key', revoked_file='./revoked.json',
                                  crl_file='./server.crl', user_cert_dir="./", username="user")

if __name__ == '__main__':
    print("Do not run this file, it just contains and example")

    exit(1)
