""" RSA class:
        This class gives you the power of RSA encryption standard """

from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, inverse

class RSA( object ):
    def __init__( self, length ):
        self.plaintext = ''
        self.ciphertext = ''
        
        self.length = length
        
        self.p = getPrime( self.length )
        self.q = getPrime( self.length )
        self.n = self.p * self.q
        self.phi = ( self.p - 1 ) * ( self.q - 1 )
        
        self.e = 65537
        self.d = inverse( self.e, self.phi )
        
        
    def encrypt( self ):
        self.ciphertext = pow( self.plaintext, self.e, self.n )
        
        
    def decrypt( self ):
        self.plaintext = pow( self.ciphertext, self.d, self.n )
        
        
    def setPlaintext( self, plaintext ):
        if( len( plaintext ) < self.n ):
            self.plaintext = bytes_to_long( plaintext.encode( 'utf-8' ) )
        else:
            print( "Plaintext is too long, try to use hybrid encryption" )
        
        
    def getPlaintext( self ):
        return "Plaintext: " + long_to_bytes( self.plaintext ).decode("utf-8")
        
        
    def getCiphertext( self ):
        return "Ciphertext: " + str( self.ciphertext )
        
        
    def getKeys( self ):
        return "Public key: " + str( self.e ) + "\nPrivate key: " + str( self.d )