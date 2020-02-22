import os
import os
import sys
import tempfile
from base64 import b64encode, b64decode
from os.path import exists
from shutil import copy2

import oyaml as yaml
from cloudmesh.common.console import Console
from cloudmesh.common.util import path_expand
from cloudmesh.common.util import readfile
from cloudmesh.common.util import writefd
from cloudmesh.configuration.security.encrypt import CmsEncryptor, KeyHandler, \
    CmsHasher
from cloudmesh.configuration.Config import Config as BaseConfig

class Config(BaseConfig):

    def encrypt(self):
        """
        Encrypts the keys listed within Config.secrets()

        Assumptions:
            1. ```cms init``` or ```cms config secinit``` has been executed
            2. Private key is in PEM format
        """

        # Helper variables
        config = Config()
        ch = CmsHasher()  # Will hash the paths to produce file name
        kh = KeyHandler()  # Loads the public or private key bytes
        ce = CmsEncryptor()  # Assymmetric and Symmetric encryptor
        counter = 0

        # Create tmp file in case reversion is needed
        named_temp = tempfile.NamedTemporaryFile(delete=True)
        revertfd = open(named_temp.name,
                        'w')  # open file for reading and writing
        yaml.dump(self.data, revertfd)  # dump file in yaml format
        revertfd.close()  # close the data fd used to backup reversion file

        # Secinit variables: location where keys are stored
        secpath = path_expand(config['cloudmesh.security.secpath'])

        # Get the public key
        kp = config['cloudmesh.security.publickey']
        print(f"pub:{kp}")

        # Load the key with PEM or OpenSSH encoding
        pub = None
        try:
            Console.msg("Attempting to read key in PEM encoding")
            pub = kh.load_key(kp, "PUB", "PEM", False)
            Console.ok("Successfully loaded key")
        except ValueError:
            try:
                Console.msg("Attempting to read key in OpenSSH encoding")
                pub = kh.load_key(kp, "PUB", "SSH", False)
                Console.ok("Successfully loaded key")
            except ValueError:
                m = "Public key must be PEM or OpenSSH encoded"
                Console.error(f"{m}")
                sys.exit()
        except Exception as e:
            Console.error(f"{e.message}")
            sys.exit()

        # Get the regular expressions from config file
        try:
            paths = self.get_list_secrets()
            for path in paths:  # for each path that reaches the key
                # Hash the path to create a base filename
                # MD5 is acceptable since security does not rely on hiding path
                h = ch.hash_data(path, "MD5", "b64", True)
                fp = os.path.join(secpath, h)
                # Check if the attribute has already been encrypted
                if exists(f"{fp}.key"):
                    Console.ok(f"\tAlready encrypted: {path}")
                else:
                    counter += 1
                    Console.ok(f"\tencrypting: {path}")
                    # Additional Authenticated Data: the cloudmesh version
                    # number is used to future-proof for version attacks
                    aad = config['cloudmesh.version']
                    b_aad = aad.encode()
                    b_aad = None

                    # Get plaintext data from config
                    pt = config[path]
                    if type(pt) != str:
                        pt = str(pt)

                    b_pt = pt.encode()

                    # Encrypt the cloudmesh.yaml attribute value
                    k, n, ct = ce.encrypt_aesgcm(data=b_pt, aad=b_aad)

                    # Write ciphertext contents
                    ct = int.from_bytes(ct, "big")
                    self.set(path, f"{ct}")

                    # Encrypt symmetric key with users public key
                    k_ct = ce.encrypt_rsa(pub=pub, pt=k)
                    # Write key to file
                    k_ct = b64encode(k_ct).decode()
                    fk = f"{fp}.key"  # use hashed filename with indicator
                    writefd(filename=fk, content=k_ct)

                    # Encrypt nonce with users private key
                    n_ct = ce.encrypt_rsa(pub=pub, pt=n)
                    # Write nonce to file
                    n_ct = b64encode(n_ct).decode()
                    fn = f"{fp}.nonce"
                    writefd(filename=fn, content=n_ct)

        except Exception as e:
            Console.error("reverting cloudmesh.yaml")
            # Revert original copy of cloudmesh.yaml
            copy2(src=named_temp.name, dst=self.config_path)
            named_temp.close()  # close (and delete) the reversion file

            # Delete generated nonces and keys
            for path in paths:
                # Calculate hashed filename
                h = ch.hash_data(path, "MD5", "b64", True)
                fp = os.path.join(secpath, h)

                # Remove key
                if os.path.exists(f"{fp}.key"):
                    os.remove(f"{fp}.key")

                # Remove nonce
                if os.path.exists(f"{fp}.nonce"):
                    os.remove(f"{fp}.nonce")
            sys.exit(f"{e}")

        named_temp.close()  # close (and delete) the reversion file
        Console.ok(f"Success: encrypted {counter} expressions")
        return counter

    def decrypt(self, ask_pass=True):
        """
        Decrypts all secrets within the config file

        Assumptions: please reference assumptions within encryption
                     section above
        """
        # Helper Classes
        config = Config()
        ch = CmsHasher()  # Will hash the paths to produce file name
        kh = KeyHandler()  # Loads the public or private key bytes
        ce = CmsEncryptor()  # Assymmetric and Symmetric encryptor
        counter = 0

        # Create tmp file in case reversion is needed
        named_temp = tempfile.NamedTemporaryFile(delete=True)
        revertfd = open(named_temp.name, 'w')  # open file for writing
        yaml.dump(config.data, revertfd)  # dump file in yaml format
        revertfd.close()  # close the data fd used to backup reversion file

        # Secinit variables: location where keys are stored
        secpath = path_expand(config['cloudmesh.security.secpath'])

        # Load the private key
        kp = config['cloudmesh.security.privatekey']
        prv = kh.load_key(kp, "PRIV", "PEM", ask_pass)

        try:
            paths = self.get_list_secrets()
            for path in paths:  # for each path that reaches the key
                # hash the path to find the file name
                # MD5 is acceptable, attacker gains nothing by knowing path
                h = ch.hash_data(path, "MD5", "b64", True)
                fp = os.path.join(secpath, h)
                if not os.path.exists(f"{fp}.key"):
                    Console.ok(f"\tAlready plaintext: {path}")
                else:
                    counter += 1
                    Console.ok(f"\tDecrypting: {path}")
                    # Decrypt symmetric key, using private key
                    k_ct = readfile(f"{fp}.key")
                    b_k_ct = b64decode(k_ct)
                    b_k = ce.decrypt_rsa(priv=prv, ct=b_k_ct)

                    # Decrypt nonce, using private key
                    n_ct = readfile(f"{fp}.nonce")
                    b_n_ct = b64decode(n_ct)
                    b_n = ce.decrypt_rsa(priv=prv, ct=b_n_ct)

                    # Version number was used as aad
                    aad = config['cloudmesh.version']
                    b_aad = aad.encode()
                    b_aad = None

                    # Read ciphertext from config
                    ct = int(config[path])
                    b_ct = ct.to_bytes((ct.bit_length() + 7) // 8, 'big')

                    # Decrypt the attribute value ciphertext
                    pt = ce.decrypt_aesgcm(key=b_k, nonce=b_n, aad=b_aad,
                                           ct=b_ct)
                    pt = pt.decode()

                    # Set the attribute with the plaintext value
                    config.set(path, pt)
        except Exception as e:
            Console.error("reverting cloudmesh.yaml")
            copy2(src=named_temp.name, dst=config.config_path)
            named_temp.close()  # close (and delete) the reversion file
            sys.exit(f"{e}")

        for path in paths:
            h = ch.hash_data(path, "MD5", "b64", True)
            fp = os.path.join(secpath, h)
            os.remove(f"{fp}.key")
            os.remove(f"{fp}.nonce")

        named_temp.close()  # close (and delete) the reversion file

        Console.ok(f"Success: decrypted {counter} expressions")
        return counter
