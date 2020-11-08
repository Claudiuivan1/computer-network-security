""" RSA class:
        This class gives you the power of RSA encryption standard """

from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes 
import Crypto
import libnum
import sys

class RSA( object ):
    def __init__( self ):
        self.plaintext = ''
        self.ciphertext = ''
        
        self.bits = 60
        self.e = 65537
        
        self.p = Crypto.Util.number.getPrime( self.bits, randfunc=get_random_bytes )
        self.q = Crypto.Util.number.getPrime( self.bits, randfunc=get_random_bytes )
        self.n = self.p*self.q
        self.phi = ( self.p-1 )*( self.q-1 )
        self.d = libnum.invmod( self.e, self.phi )
        
    def encrypt( self ):
        self.ciphertext = pow( self.plaintext, self.e, self.n )
        
    def decrypt( self ):
        self.plaintext = long_to_bytes( pow( self.ciphertext, self.d, self.n ) )
        
    def setPlaintext( self, plaintext ):
        self.plaintext = bytes_to_long( plaintext.encode( 'utf-8' ) )
        
    def getPlaintext( self ):
        return self.plaintext
        
    def getCiphertext( self ):
        return self.ciphertext