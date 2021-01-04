import atakofthecerts

# Generate initial certs and copy the serve certs to the correct directory
# This is the same as running "sudo python3 atackofthecerts.py -a -c -i 192.168.1.100"
with atakofthecerts.AtakOfTheCerts() as aotc:
    aotc.generate_ca()
    aotc.generate_auto_certs(ip="192.168.1.100", copy=True)

# Generate a server certificate for a server at 192.168.1.100, a user certificate for the username test_user
# then generates a zip based ATAK data package for client connection
with atakofthecerts.AtakOfTheCerts() as aotc:
    aotc.generate_ca()
    aotc.bake(cn="192.168.1.100", cert="server")
    aotc.bake(cn="test_user", cert="user")
atakofthecerts.generate_zip(server_address="192.168.1.100", server_filename="pubserver.p12", user_filename="user.p12")

if __name__ == '__main__':
    print("Do not run this file, it just contains and example")
    exit(1)
