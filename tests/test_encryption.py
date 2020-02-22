#########################################################################
# pytest -v --capture=no tests/test_encryption.py
# pytest -v  tests/test_encryption.py
# pytest -v --capture=no  tests/test_encryption..py::Test_name::<METHODNAME>
#########################################################################
""" run with

pytest -v --capture=no tests/test_encryption.py

"""

import os
import pytest
import tempfile
from cloudmesh.configuration.Config import Config
from cloudmesh.common.util import path_expand, writefile, readfile
#from cloudmesh.security.encrypt import KeyHandler, CmsEncryptor
from cloudmesh.configuration.security.encrypt import KeyHandler, CmsEncryptor
from shutil import copy2

@pytest.mark.incremental
class TestEncrypt:

    def test_sec_section_exists(self):
        default_path = "cloudmesh/configuration/etc/cloudmesh.yaml"
        config = Config(default_path)
        res = config['cloudmesh.security']
        assert (res != [])

    def test_kh_load_public(self):
        # Generate new keys
        kh = KeyHandler()
        r = kh.new_rsa_key( byte_size = 2048 )
        u = kh.serialize_key(key = kh.get_pub_key(priv=r), key_type="PUB", 
                        encoding="PEM", format="SubjectInfo", ask_pass=False)

        # Write keys to temp
        tmp = tempfile.NamedTemporaryFile(delete=True)
        tmp.write(u)
        tmp.seek(0)

        # Load the keys
        tu = kh.load_key(tmp.name, key_type="PUB", encoding="PEM", ask_pass=False)

        # Serialize the bytes
        t = kh.serialize_key(key=tu, key_type="PUB", encoding="PEM", 
                            format="SubjectInfo", ask_pass = False )

        #Check if they are the same
        assert(t == u)

    def test_kh_load_private(self):
        # Generate new keys
        kh = KeyHandler()
        r = kh.new_rsa_key( byte_size = 2048 )
        r = kh.serialize_key( key = r, key_type = "PRIV", encoding = "PEM",
                            format = "PKCS8", ask_pass = False )

        # Write keys to temp
        tmp = tempfile.NamedTemporaryFile(delete=True)
        tmp.write(r)
        tmp.seek(0)

        # Load the keys
        tr = kh.load_key(tmp.name, key_type="PRIV", encoding="PEM", ask_pass=False)

        # Serialize the bytes
        t = kh.serialize_key(key=tr, key_type="PRIV"
                        , encoding="PEM", format="PKCS8", ask_pass=False)

        #Check if they are the same
        assert(t == r)

    def test_RSA_encryption(self):
        ce = CmsEncryptor()
        data = ce.getRandomBytes()

        # Generate new keys
        kh = KeyHandler()
        r = kh.new_rsa_key( byte_size = 2048 )
        u = kh.get_pub_key( priv = r )

        # Encrypt the data
        ct = ce.encrypt_rsa(pub=u, pt=data, padding_scheme="OAEP")

        # Decrypt the data
        pt = ce.decrypt_rsa(priv=r, ct = ct, padding_scheme="OAEP")

        # Ensure the data is equivalent
        assert(data == pt)

    def test_AESGCM_nonces(self):
        # Given the same data and aad will the nonces be equal?
        ce = CmsEncryptor()
        data = ce.getRandomBytes()
        aad = b"test"
        # Given two callings on cipher the nonce should never repeat
        k1, n1, ct1 =ce.encrypt_aesgcm(data=data, aad=aad)
        k2, n2, ct2 = ce.encrypt_aesgcm(data=data, aad=aad)
        assert((n1 != n2) or (k1 != k2))

    def test_AESGCM_encryption(self):
        # Will the encryption and decryption of arbitrary data be equivalent?
        ce = CmsEncryptor()
        data = ce.getRandomBytes()
        aad = b"test"
        k, n, ct = ce.encrypt_aesgcm(data=data, aad=aad)
        pt = ce.decrypt_aesgcm(key=k, nonce=n, aad=aad, ct=ct)
        assert (pt == data)
