import time
import hashlib
import json
import requests
import base64
import ecdsa

def generate_ECDSA_keys():
    """This function takes care of creating your private and public (your address) keys.
    It's very important you don't lose any of them or those wallets will be lost
    forever. If someone else get access to your private key, you risk losing your coins.

    private_key: str
    public_ley: base64 (to make it shorter)
    """
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1) #this is your sign (private key)
    private_key = sk.to_string().hex() #convert your private key to hex
    vk = sk.get_verifying_key() #this is your verification key (public key)
    public_key = vk.to_string().hex()
    #we are going to encode the public key to make it shorter
    public_key = base64.b64encode(bytes.fromhex(public_key))

    filename = input("Write the name of your new key: ") + ".txt"
    with open(filename, "w") as f:
        f.write("Private key: {0}\nPublic key: {1}".format(private_key, public_key.decode()))
    print("Your new public key and private key are now in the file {0}".format(filename))

def sign_ECDSA_msg(private_key):
    """Sign the message to be sent
    private_key: must be hex

    return
    signature: base64 (to make it shorter)
    message: str
    """
    # Get timestamp, round it, make it into a string and encode it to bytes
    message = str(round(time.time()))
    bmessage = message.encode()
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    signature = base64.b64encode(sk.sign(bmessage))
    return signature, message

while True:
    response = None
    while response not in ["1", "2"]:
        response = input("""\n\nWhat do you want to do?
        1. Generate new key pair
        2. Save data to BlockChain\n""")
    if response == "1":
        generate_ECDSA_keys()
    if response == "2":
        private_key = input('Type Private Key:')
        public_key = input('Type Public Key:')
        password = input('Type Server Password:')
        data = input('Type Data:')
        sign, msg = sign_ECDSA_msg(private_key)
        params = { "pub" : public_key, "sign" : sign, "msg" : msg, "data" : data, "password" : password }
        request = requests.get('https://rdpbc.cn.utools.club/api/save',params = params)
        print(request.content)
