from TypeChecking.Annotations import typecheck
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


class Oracle():
    """
    Bleichebacher's oracle implementing methods available to eve.
    """

    @typecheck
    def __init__(self, secret):
        """
        Setup keys, secret message and encryption/decryption schemes.
        """
        
        self._key = RSA.generate(1024)
        self._pkcs = PKCS1_v1_5.new(self._key)
        #self._secret = b'Testing Bleichenbachers RSA Attack !!!!!!!!!!!'
        self._secret = secret.encode("utf-8")
        self._pkcsmsg = self._pkcs.encrypt(self._secret)
        

    
    @typecheck
    def get_n(self) -> int:
        """
        Returns the public RSA modulus.
        """
        return self._key.n

    @typecheck
    def get_e(self) -> int:
        """
        Returns the public RSA exponent.
        """
        return self._key.e

    @typecheck
    def get_k(self) -> int:
        """
        Returns the length of the RSA modulus in bytes.
        """
        return (self._key.size_in_bits() + 1) // 8

    @typecheck
    def eavesdrop(self) -> bytes:
        return self._pkcsmsg

    @typecheck
    def decrypt(self, ciphertext: bytes) -> bool:
        """
        Check if it wants to decrypt the PKCS#1 1.5
        (i.e if the padding is correctly formatted) 
        """   
        
        sentinel = "Error"        
        plaintest = self._pkcs.decrypt(ciphertext, sentinel="Error")
       
        if plaintest == "Error": 
            #print("Returning False")
            return False
        elif plaintest == b'':
            #print("Returning False")
            return False
        else:
            print("Found one!  Returning True")
            return True
            
  