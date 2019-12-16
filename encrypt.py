import os
import sys
from base64 import b64encode
import getpass

from cloudmesh.common.Shell import Shell
from cloudmesh.common.console import Console
from cloudmesh.common.util import path_expand, readfile, writefd, yn_choice
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CmsEncryptor:
    """ 
    Encrypts bytes for CMS
    I) key generation is outside scope of CmsEncryptor
      1) Generating 2048 bit RSA Private and Public PEM files
        A) Debian
            a) Ensure openssl is installed
            b) Execute: openssl genrsa -aes256 -out <priv_key_name>
            c) Execute:
               openssl rsa -in <priv_name> -outform PEM -pubout -out <pub_name>

      2) Generating 2048 bit RSA Private and Public SSH keys
        A) Debian
            a) ensure ssh-keygen is installed
            b) Execute: ssh-keygen -t rsa -m pem -f <base_priv_and_pub_name>

      2) Generating 384 bit ECC key
        A) Debian 
            a) TODO
    """

    def __init__(self, debug=False):
        self.debug = debug
        self.tmp = path_expand("~/.cloudmesh/tmp")

    # noinspection PyPep8Naming
    def getRandomBytes(self, len_bytes=32):
        rand_bytes = os.urandom(len_bytes)
        return rand_bytes

    # noinspection PyPep8Naming
    def getRandomInt(self, len_bytes=32, order="big"):
        rb = self.getRandomBytes(len_bytes)
        rand_int = int.from_bytes(rb, byteorder=order)
        return rand_int

    def encrypt_rsa(self, pub=None, pt=None, padding_scheme="OAEP"):
        if pub is None:
            Console.error("empty key argument")
            sys.exit()

        if pt is None:
            Console.error("attempted to encrypt empty data")
            sys.exit()

        elif not type(pt) == bytes:
            pt = pt.encode()

        pad = None
        if padding_scheme == "OAEP":
            pad = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                               algorithm=hashes.SHA256(),
                               label=None)
        else:
            Console.error("Unsupported padding scheme")
            sys.exit()

        return pub.encrypt(pt, pad)

    def decrypt_rsa(self, priv=None, ct=None, padding_scheme="OAEP"):
        if priv is None:
            Console.error("empty key arugment")
            sys.exit()
        if ct is None:
            Console.error("attempted to decrypt empty data")
            sys.exit()
        pad = None
        if padding_scheme == "OAEP":
            pad = padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
        else:
            Console.error("Unsupported padding scheme")
            sys.exit()

        # return priv.decrypt( ct, pad ).decode()
        return priv.decrypt(ct, pad)

    def decrypt_aesgcm(self, key=None, nonce=None, aad=None, ct=None):
        aesgcm = AESGCM(key)
        pt = aesgcm.decrypt(nonce, ct, aad)
        return pt

    def encrypt_aesgcm(self, data=None, aad=None):
        """
        @param: bytes: the plaintext data 
        @param: bytes: the additional authenticated data (can be public)
        @return: 
            - bytes: AESGCM key object
            - bytes: nonce (random data)
            - bytes: ciphertext
        """
        if data is None:
            Console.error("Attempted to encrypt empty data")
            sys.exit()

        # ALWAYS generate a new nonce. 
        # ALL security is lost if same nonce and key are used with diff text 
        nonce = self.getRandomBytes(12)
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, data, aad)

        return key, nonce, ct

    def encrypt_file(self, infile=None, outfile=None, enc_aes_key=True,
                     inkey=None):
        """
        Encrypts the file located at filepath using AES-GCM, and encrypt the
        AES key with RSA if indicated. It is the responsibility of the caller 
        to handle the returned key and nonce. 

        @param infile:      Full path to the file that will be encrypted
        @param outfile:     Full path to the desired output location
        @param enc_aes_key: Indicate if AES key should be encrypted with pubkey
        @param inkey:       Full path to the PEM encoded public key 
        @return:
            - bytes: AES-GCM key
            - bytes: nonce (one time random data)
        """

        # Check if filepath exists
        if not os.path.exists(infile):
            Console.error(f"{infile} does not exists")
            sys.exit()

        # Check if the key exists
        if enc_aes_key and not os.path.exists(inkey):
            Console.error(f"{inkey} does not exists")
            sys.exit()

        # Check if filepath is directory
        if os.path.isdir(infile):
            Console.error(f"{infile} is a directory")
            sys.exit()

        # Assign the outfile name if needed
        if outfile is None:
            outfile = os.path.basename(infile) + ".enc"

        # Read the file contents
        contents = readfile(infile)
        contents = contents.encode()

        # Encrypt the file using Symmetric AES-GCM encryption
        k, n, ct = self.encrypt_aesgcm(data=contents, aad=None)

        # Encrypt the key if desired
        if enc_aes_key:
            kh = KeyHandler()
            u = kh.load_key(path=inkey, key_type="PUB",
                            encoding="PEM", ask_pass=False)
            k = self.encrypt_rsa(pub=u, pt=k)

        # Encode the data as integers
        cipher = int.from_bytes(ct, 'big')

        # Write outfile and remove infile
        writefd(filename=outfile, content=str(cipher))
        Shell.rm(infile)

        return k, n

    def decrypt_file(self, infile=None, aes_key=None, nonce=None,
                     outfile=None, dec_aes_key=True, inkey=None, has_pass=True):
        """
        Decrypts the file located at the infile with AES-GCM using the passed
        in bytes of the key and nonce that was generated during encryption. 
        The AES key will be decrypted using RSA if indicated. 
        Note: This is untested with large data files

        @param infile:      Full path to the file that will be decrypted
        @param aes_key:     Bytes of the AES key generated at encryption
        @param nonce:       Bytes of the nonce generated at encryption
        @param outfile:     Full path to the desired output location
        @param dec_aes_key: Indicate if AES key should be decrypted with pubkey
        @param inkey:       Full path to the PEM encoded public key 
        @param has_pass:    Indicates if the private key is password protected
        """
        # TODO: Test with large data files (10GB+)

        # Check if filepath exists
        if not os.path.exists(infile):
            Console.error(f"{infile} does not exists")
            sys.exit()

        # Check if the key exists
        if dec_aes_key and not os.path.exists(inkey):
            Console.error(f"{inkey} does not exists")
            sys.exit()

        # Check if filepath is directory
        if os.path.isdir(infile):
            Console.error(f"{infile} is a directory")
            sys.exit()

        # Assign the outfile name if needed
        if outfile is None:
            name = os.path.basename(infile)
            if name[:-4] == '.enc':
                outfile = infile[:-4]
            else:
                outfile = infile

        # Decrypt AES key if indicated
        if dec_aes_key:
            kh = KeyHandler()
            r = kh.load_key(path=inkey, key_type="PRIV",
                            encoding="PEM", ask_pass=has_pass)
            aes_key = self.decrypt_rsa(priv=r, ct=aes_key)

        # Read file and calculate bytes
        ct = int(readfile(filename=infile))
        b_ct = ct.to_bytes((ct.bit_length() + 7) // 8, 'big')

        # Decrypt ciphertext
        pt = self.decrypt_aesgcm(key=aes_key, nonce=nonce, aad=None, ct=b_ct)
        writefd(filename=outfile, content=pt.decode())
        Shell.rm(infile)


class CmsHasher:
    def __init__(self, data=None, data_type=str):
        # Check if data is empty
        if data is not None:
            # Ensure proper data type
            if data_type is str:
                self.data = data.encode()
            elif data_type is bytes:
                self.data = data
            else:
                Console.error(f"data_type:{data_type} is not supported")
                sys.exit()

    def hash_data(self, data=None, hash_alg="SHA256"
                  , encoding=False, clean=False):
        digest = None
        if hash_alg == "MD5":
            # !!!!!!!!!!!!!!!!!!!!!!! Warning !!!!!!!!!!!!!!!!!!!!!!!!
            # This hash has know vulnerabilities. 
            # ONLY used this when the data does not need to be secert. 
            # !!!!!!!!!!!!!!!!!!!!!!! Warning !!!!!!!!!!!!!!!!!!!!!!!!
            digest = hashes.Hash(hashes.MD5(), backend=default_backend())
        elif hash_alg == "SHA256":
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        else:
            Console.error("Unsupported Hashing algorithm")
            sys.exit()

        if type(data) is str:
            data = data.encode()
        digest.update(data)
        hashed = digest.finalize()

        # Encode data if requested
        if not encoding:
            """no op, just for check"""
        elif encoding == "b64":
            hashed = b64encode(hashed).decode()
        else:
            Console.error("Unknown encoding requested")
            sys.exit()

        # Clean data for system purposes if requested
        if clean:
            remove_chars = ['+', '=', '\\',
                            '/']  # special dir chars on typical os
            for char in remove_chars:
                if char in hashed:
                    hashed = hashed.replace(char, "")

        return hashed


class KeyHandler:
    """ 
    Responsible for the loading and creation of keys
    """

    def __init__(self, debug=False, priv=None, pub=None, pem=None):
        # CMS debug parameter
        self.debug = debug
        # pyca Key Objects
        self.priv = priv
        self.pub = pub
        self.pem = pem

    def new_rsa_key(self, byte_size=2048):
        """
        Generates a new RSA private key 
        @param: int: size of key in bytes
        @param: bol: indicates if app must prompt for password
        return: serialized bytes of private the RSA key
        """
        self.priv = rsa.generate_private_key(
            public_exponent=65537,  # do NOT change this!!!
            key_size=byte_size,
            backend=default_backend()
        )

        return self.priv

    def get_pub_key(self, priv=None):
        """
        Given a Pyca private key instance return a Pyca public key instance
        @param priv: the PYCA private key
        return: the pyca RsaPublicKey
        """
        if priv is None:
            Console.error("No key was given")
            sys.exit()
        elif isinstance(priv, rsa.RSAPrivateKey):
            return priv.public_key()
        else:
            raise UnsupportedAlgorithm

    def serialize_key(self, debug=False, key=None, key_type="PRIV",
                      encoding="PEM", format="PKCS8", ask_pass=True):
        """
        @param: debug:      cloudmesh debug flag
        @param: key:        pyca key object
        @param: key_type:   the type of key file [PRIV, PUB]
        @param: encoding:   the type of encoding [PEM, SSH]
        @param: format:     private [PKCS8, OpenSSL], Public [SubjectInfo, SSH]
        @param: ask_pass:   Indicates if the key should have a password
                            (True,False)
        return:             serialized key bytes of the key
        """
        # TODO: add try-catching
        # Ensure the key is initialized
        if key is None:
            if key_type == "PRIV":
                if self.priv is None:
                    Console.error("No key given")
                    sys.exit()
                else:
                    key = self.priv
            elif key_type == "PUB":
                if self.pub is None:
                    Console.error("No key given")
                    sys.exit()
                else:
                    key = self.pub
            else:
                Console.error("No key given")
                sys.exit()

        # Discern formating based on if key is public or private
        key_format = None
        if key_type == "PRIV":
            key_format = serialization.PrivateFormat
        elif key_type == "PUB":
            key_format = serialization.PublicFormat
        else:
            Console.error("key needs to be PRIV or PUB")
            sys.exit()

        # Discern formatting of key
        if key_type == "PRIV":
            if format == "PKCS8":
                key_format = key_format.PKCS8
            elif format == "OpenSSL":
                key_format = key_format.TraditionalOpenSSL
            else:
                Console.error("Unsupported private key format")
                sys.exit()
        elif key_type == "PUB":
            if format == "SubjectInfo":
                key_format = key_format.SubjectPublicKeyInfo
            elif format == "SSH":
                key_format = key_format.OpenSSH
            else:
                Console.error("Unsupported public key format")
                sys.exit()

        # Discern encoding
        encode = None
        if encoding == "PEM":
            encode = serialization.Encoding.PEM
        elif encoding == "SSH":
            encode = serialization.Encoding.OpenSSH
        else:
            Console.error("Unsupported key encoding")
            sys.exit()

        # Discern encryption algorithm (Private keys only)
        # This also assigns the password if given
        enc_alg = None
        if key_type == "PRIV":
            if not ask_pass:
                m = "Key being created without password. "\
                    "This is not recommended."
                Console.warning(m)
                enc_alg = serialization.NoEncryption()
            else:
                pwd = self.requestPass("Password for the new key:")
                if pwd == "":
                    enc_alg = serialization.NoEncryption()
                else:
                    pwd = str.encode(pwd)
                    enc_alg = serialization.BestAvailableEncryption(pwd)

        # Serialize key
        sk = None
        if key_type == "PUB":
            sk = key.public_bytes(encoding=encode, format=key_format)
        elif key_type == "PRIV":
            sk = key.private_bytes(encoding=encode, format=key_format,
                                   encryption_algorithm=enc_alg)
        return sk

    def write_key(self, key=None, path=None, mode="wb"):
        """
        Writes the key to the path, creating directories as needed"
        @param key:     The data being written yca key instance
        @param path:    full path including file name
        """
        # Check if the key is empty
        if key is None:
            Console.error("Key is empty")
            sys.exit()

        if path is None:
            Console.error("Path is empty")
            sys.exit()

        # Create directories as needed for the key
        dirs = os.path.dirname(path)
        if not os.path.exists(dirs):
            Shell.mkdir(dirs)

        # Check if file exists at locations
        if os.path.exists(path):
            Console.info(f"{path} already exists")
            ovwr_r = yn_choice(message=f"overwrite {path}?", default="N")
            if not ovwr_r:
                Console.info(f"Not overwriting {path}. Quitting")
                sys.exit()

        # Write the file
        writefd(filename=path, content=key, mode=mode)

    def load_key(self, path="", key_type="PUB", encoding="SSH", ask_pass=True):
        """
        Loads a public or private key from the path using pyca
        @param: str: path to file being loaded
        @param: str: indicates if key is public (PUB) or private (PRIV)
        @param: str: indicates encoding of file (SSH, PEM)
        @param: bol: Flag to ask for the key's password 
        return: rsa.RSAPublicKey, rsa.RSAPrivate, or None
        """
        # Discern target key instance
        key_instance = None
        if key_type == "PUB":
            key_instance = rsa.RSAPublicKey
        elif key_type == "PRIV":
            key_instance = rsa.RSAPrivateKey
        else:
            Console.error("Unsupported key type")
            sys.exit()

        # Discern function from encoding and key type
        load_function = None
        if encoding == "SSH" and key_type == "PUB":
            load_function = serialization.load_ssh_public_key
        elif encoding == "PEM":
            if key_type == "PRIV":
                load_function = serialization.load_pem_private_key
            elif key_type == "PUB":
                load_function = serialization.load_pem_public_key
            else:
                Console.error("Unsupported key type for PEM keys")
                sys.exit()
        else:
            Console.error("Unsupported encoding and key-type pairing")
            sys.exit()

        # Discern password
        password = None
        if not ask_pass:
            password = None
        else:  # All other cases should request password
            password = self.requestPass(
                f"Password for {path} [press enter if none]:")
            if password == "":
                password = None
            else:
                password = password.encode()

        # Read key file bytes
        data = readfile(path, mode='rb')

        # Attempt to load the formatted contents
        try:
            key = None
            if key_type == "PUB":
                key = load_function(data, default_backend())
            elif key_type == "PRIV":
                key = load_function(data, password, default_backend())

            # Check if key instance is correct
            if isinstance(key, key_instance):
                return key
            else:
                Console.error(f"Key instance must be {key_instance}")
                sys.exit()

        except ValueError as e:
            Console.error(f"Could not properly decode {encoding} key")
            raise e
        except TypeError as e:
            Console.error("""Password mismatch either: 
            1. given a password when file is not encrypted 
            2. Not given a password when file is encrypted""")
            sys.exit()
        except UnsupportedAlgorithm as e:
            Console.error("Unsupported format for pyca serialization")
            sys.exit()
        except Exception as e:
            Console.error(f"{e}")
            sys.exit()

    # noinspection PyPep8Naming
    def requestPass(self, prompt="Password for key:"):
        try:
            pwd = getpass.getpass(prompt)
            return pwd
        except getpass.GetPassWarning:
            Console.error("Danger: password may be echoed")
            sys.exit()
        except Exception as e:
            raise e
