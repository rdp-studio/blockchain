import time
import hashlib
import json
import requests
import base64
from flask import Flask, request, render_template, jsonify
import ecdsa

web = Flask(__name__)

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        """Returns a new Block object. Each block is "chained" to its previous
        by calling its unique hash.
        Args:
            index (int): Block number.
            timestamp (int): Block creation timestamp.
            data (str): Data to be save.
            previous_hash(str): String representing previous block unique hash.
        Attrib:
            index (int): Block number.
            timestamp (int): Block creation timestamp.
            data (str): Data to be save.
            previous_hash(str): String representing previous block unique hash.
            hash(str): Current block unique hash.
        """
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    def hash_block(self):
        """Creates the unique hash for the block. It uses sha256."""
        sha = hashlib.sha256()
        sha.update((str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash)).encode('utf-8'))
        return sha.hexdigest()


def create_genesis_block():
    """To create each block, it needs the hash of the previous one. First
    block has no previous, so it must be created manually (with index zero
     and arbitrary previous hash)"""
    return Block(0, time.time(), "RDPStudio BlockChain Genesis Block", "0")

def save_chain():
    fo = open("chain.txt", "w")
    fo.write(expand_data())
    fo.close()

def expand_data():
    chain_to_send_json = []
    for block in BLOCKCHAIN:
        block = {
            "index": str(block.index),
            "timestamp": str(block.timestamp),
            "data": str(block.data),
            "hash": str(block.hash),
            "previous_hash": str(block.previous_hash)
        }
        chain_to_send_json.append(block)
        return str(chain_to_send_json)

def load_chain():
    fo = open("chain.txt", "r")
    data = fo.read()
    print(data)
    tempchain = []
    for tempblock in data:
        print(tempblock)
        print(tempblock.replace("'", '"'))
        tempblock = json.loads(tempblock.replace("'", '"'))
        tempchain.append(Block(int(tempblock['index']),int(tempblock['timestamp']),str(tempblock['data']),str(tempblock['previous_hash'])))
    BLOCKCHAIN = tempchain
    fo.close()

def validate_signature(public_key, signature, message):
    """Verifies if the signature is correct. This is used to prove
    it's you (and not someone else) trying to do a data with your
    address. Called when a user tries to submit a new data.
    """
    public_key = (base64.b64decode(public_key)).hex()
    signature = base64.b64decode(signature)
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
    # Try changing into an if/else statement as except is too broad.
    try:
        return vk.verify(signature, message.encode())
    except:
        return False

global BLOCKCHAIN
BLOCKCHAIN = [create_genesis_block()] # for init
#load_chain() # for startup

@web.route('/')
def explorer():
    save_chain()
    return render_template("page.html",txt = BLOCKCHAIN)

@web.route('/api/data')
def get_block_data():
    save_chain()
    id = request.args.get("id")
    return jsonify( {'code' : '200','block_data' : BLOCKCHAIN[int(id)].data } )

@web.route('/api/chain')
def chain():
    save_chain()
    return expand_data()

@web.route('/api/save')
def save_to_chain():
    try:
        status = validate_signature(request.args.get("pub"),request.args.get("sign"),request.args.get("msg"))
    except:
        return jsonify( {'code' : '400','message' : 'Wrong Sig or no sig' } )
    if status and (request.args.get("password") == "123456"):
        last_block = BLOCKCHAIN[-1]
        BLOCKCHAIN.append(Block(last_block.index + 1, time.time(), str(request.args.get("data")), last_block.hash))
        save_chain()
        return jsonify( {'code' : '200','block_id' : last_block.index + 1 } )
    else:
        return jsonify( {'code' : '400','message' : 'Wrong PWD' } )

web.run(host = "0.0.0.0", port = "1245")
