""" AES128 class:
        This class gives you the power of AES128 encryption standard with 5 different operation modes
        :param key: Secret key
        :param mode: Operation mode (ECB, CBC, CFB, OFB, CTR) """
        
import random

class AES128( object ):
    def __init__( self, key, mode ):
        self.block_size = 128
        self.nb = 4
        self.nk = 4
        self.nr = 10
        self.mode = mode
        self.key = ['0x2b', '0x7e', '0x15', '0x16', '0x28', '0xae', '0xd2', '0xa6', '0xab', '0xf7', '0x15', '0x88', '0x09', '0xcf', '0x4f', '0x3c']#self.splitKey( key )
        self.iv = self.generateIv()
        
        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]
        
        self.rsbox = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        ]

        self.mix_matrix = [
            0x02, 0x03, 0x01, 0x01,
            0x01, 0x02, 0x03, 0x01,
            0x01, 0x01, 0x02, 0x03,
            0x03, 0x01, 0x01, 0x02
        ]
        
        self.rmix_matrix = [
            0x0e, 0x0b, 0x0d, 0x09,
            0x09, 0x0e, 0x0b, 0x0d,
            0x0d, 0x09, 0x0e, 0x0b,
            0x0b, 0x0d, 0x09, 0x0e
        ]
        
        self.rCon = [
            ['0x01', '0x00', '0x00', '0x00'],
            ['0x02', '0x00', '0x00', '0x00'],
            ['0x04', '0x00', '0x00', '0x00'],
            ['0x08', '0x00', '0x00', '0x00'],
            ['0x10', '0x00', '0x00', '0x00'],
            ['0x20', '0x00', '0x00', '0x00'],
            ['0x40', '0x00', '0x00', '0x00'],
            ['0x80', '0x00', '0x00', '0x00'],
            ['0x1b', '0x00', '0x00', '0x00'],
            ['0x36', '0x00', '0x00', '0x00']
        ]
        
        self.w = self.keyExpansion( key )
        
        self.splitted = []
        self.ciphertext = []
        
                
    def splitText( self, string ): # Split plaintext in blocks of specified size
        out = []
        subarray = []
        for i in range( len( string ) // 2 ):
            subarray.append( "0x" + string[i*2:i*2+2] )
            if( (i+1) % 16 == 0 ):
                out.append( subarray )
                subarray = []
        if( len( subarray ) > 0 ):
            out.append(subarray)
        return out
        
        
    def pad( self, text, mode ): 
        n = 16 - len( text[-1] )
        if( mode == 'PKCS' ):
            if( n > 0 ):
                for i in range( n ):
                    text[-1].append( hex( n ) )
            else:
                text.append( ["0x10"] * 16 )
        elif( mode == 'ZERO' ):
            if( n > 0 ):
                for i in range( n ):
                    text[-1].append( "0x00" )
        return text
        
    def unpad( self, text, mode ): 
        n = 16 - int( text[-1][-1], 16 )
        if( mode == 'PKCS' ):
            if( n > 0 ):
                for i in range( 16 - n ):
                    text[-1].pop()
            else:
                text.pop()
        elif( mode == 'ZERO' ):
            if( n > 0 ):
                for i in range( n ):
                    text[-1].pop()
        return text
        
        
    def splitKey( self, string ): # Split key in blocks of specified size
        out = []
        for i in range( len(string) // 2 ):
            out.append( "0x" + string[i*2:i*2+2] )
        return out
        
        
    def generateIv( self ):
        iv = []
        for i in range( 0, 16 ):
            iv.append( hex( random.randint(0, 255) ) )
        return iv
        
        
    def encrypt( self ):
        ciphertext = []
        plaintext = [] + self.splitted
        plaintext = self.pad( plaintext, 'PKCS' )
        
        for i in range( 0, len( plaintext ) ):
            if( self.mode == 'ECB' ):
                block = plaintext[i]
                block = self.encryptBlock( block )
            elif( self.mode == 'CBC' ):
                block = plaintext[i]
                if( i == 0 ):
                    block = self.xor( block, self.iv )
                else:
                    block = self.xor( block, ciphertext[i-1] )
                block = self.encryptBlock( block )
            elif( self.mode == 'CFB' ):
                if( i == 0 ):
                    block = [] + self.iv
                else:
                    block = ciphertext[i-1]
                block = self.encryptBlock( block )
                block = self.xor( block, plaintext[i] )
            elif( self.mode == 'OFB' ):
                if( i == 0 ):
                    block = [] + self.iv
                else:
                    block = temp
                block = self.encryptBlock( block )
                temp = block
                block = self.xor( block, plaintext[i] )
            elif( self.mode == 'CTR' ):
                if( i == 0 ):
                    temp = [] + self.iv
                else:
                    self.incrementCounter()
                block = [] + self.iv
                block = self.encryptBlock( block )
                block = self.xor( block, plaintext[i] )
            if( self.mode == 'CTR' ):
                self.iv = [] + temp
            ciphertext.append( block )
            
        self.ciphertext = [] + ciphertext
        
        
    def encryptBlock( self, block ):
        key = self.w[0] + self.w[1] + self.w[2] + self.w[3]
        block = self.addRoundKey( block, key )
        for i in range( 1, self.nr ):
            block = self.subBytes( block )
            block = self.shiftRows( block )
            block = self.mixColumns( block )
            key = self.w[i*4] + self.w[i*4+1] + self.w[i*4+2] + self.w[i*4+3]
            block = self.addRoundKey( block, key )
        block = self.subBytes( block )
        block = self.shiftRows( block )
        block = list( map( hex, block ) )
        key = self.w[(i+1)*4] + self.w[(i+1)*4+1] + self.w[(i+1)*4+2] + self.w[(i+1)*4+3]
        block = self.addRoundKey( block, key )
        return block
        
        
    def subBytes( self, block ): # Sostituzione non lineare di tutti i byte che vengono rimpiazzati secondo una specifica tabella.
        out = []
        for i in block:
            if( len( i ) == 3 ):
                row = 0
            else:
                row = int( i[2], 16 )
            if( len( i ) == 3 ):
                col = int( i[2], 16 )
            else:
                col = int( i[3], 16 )
            out.append( self.sbox[col+16*(row)] )
        return out
            
        
    def shiftRows( self, block ): # Spostamento dei byte di un certo numero di posizioni dipendente dalla riga di appartenenza.
        out = [ block[0], block[5], block[10], block[15], 
                block[4], block[9], block[14], block[3], 
                block[8], block[13], block[2], block[7], 
                block[12], block[1], block[6], block[11] ]
        return out   
        
        
    def mixColumns( self, block ): # Combinazione dei byte con un'operazione lineare, i byte vengono trattati una colonna per volta.
        out = [0] * self.nb * 4
        for i in range( 0, self.nb ):
            for j in range ( 0, self.nb ):
                for k in range( 0, self.nb ):
                    out[j+i*self.nb] = int( self.byteXor( out[j+i*self.nb], self.polyMult( self.mix_matrix[k+j*self.nb], block[k+i*self.nb] ) ), 16 )
                out[j+i*self.nb] = hex( out[j+i*self.nb] )
        return out
            
        
    def addRoundKey( self, block, key ): # Ogni byte della tabella viene combinato con la chiave di sessione, la chiave di sessione viene calcolata dal gestore delle chiavi.
        out = [0] * 16
        for i in range( 0, 16 ):
            out[i] = self.byteXor( int( block[i], 16 ), int( key[i], 16 ) )
        return out
        
        
    def decrypt( self ):
        plaintext = []
        ciphertext = [] + self.ciphertext
        
        for i in range( 0, len( ciphertext ) ):
            if( self.mode == 'ECB' ):
                block = ciphertext[i]
                block = self.decryptBlock( block )
            elif( self.mode == 'CBC' ):
                block = ciphertext[i]
                block = self.decryptBlock( block )
                if( i == 0 ):
                    block = self.xor( block, self.iv )
                else:
                    block = self.xor( block, plaintext[i-1] )
            elif( self.mode == 'CFB' ):
                if( i == 0 ):
                    block = [] + self.iv
                else:
                    block = ciphertext[i-1]
                block = self.encryptBlock( block )
                block = self.xor( block, ciphertext[i] )
            elif( self.mode == 'OFB' ):
                if( i == 0 ):
                    block = [] + self.iv
                else:
                    block = temp
                block = self.encryptBlock( block )
                temp = block
                block = self.xor( block, ciphertext[i] )
            elif( self.mode == 'CTR' ):
                if( i == 0 ):
                    temp = [] + self.iv
                else:
                    self.incrementCounter()
                block = [] + self.iv
                block = self.decryptBlock( block )
                block = self.xor( block, self.ciphertext[i] )
            if( self.mode == 'CTR' ):
                self.iv = [] + temp
            plaintext.append( block )
            
        plaintext = self.unpad( plaintext, 'PKCS' )
        self.splitted = [] + plaintext
        
        
    def decryptBlock( self, block ):
        key = self.w[(self.nr+1)*self.nb-4] + self.w[(self.nr+1)*self.nb-3] + self.w[(self.nr+1)*self.nb-2] + self.w[(self.nr+1)*self.nb-1]
        block = self.addRoundKey( block, key )
        for i in range( 1, self.nr ):
            block = self.invShiftRows( block )
            block = self.invSubBytes( block )
            key = self.w[(self.nr+1)*self.nb-i*4-4] + self.w[(self.nr+1)*self.nb-i*4-3] + self.w[(self.nr+1)*self.nb-i*4-2] + self.w[(self.nr+1)*self.nb-i*4-1]
            block = list( map( hex, block ) )
            block = self.addRoundKey( block, key )
            block = list( map( lambda x: int( x, 16 ), block ) )
            block = self.invMixColumns( block )
        block = self.invShiftRows( block )
        block = self.invSubBytes( block )
        block = list( map( hex, block ) )
        key = self.w[0] + self.w[1] + self.w[2] + self.w[3]
        block = self.addRoundKey( block, key )
        return block
        
        
    def invSubBytes( self, block ): # Sostituzione non lineare di tutti i byte che vengono rimpiazzati secondo una specifica tabella.
        out = []
        for i in block:
            if( len( i ) == 3 ):
                row = 0
            else:
                row = int( i[2], 16 )
            if( len( i ) == 3 ):
                col = int( i[2], 16 )
            else:
                col = int( i[3], 16 )
            out.append( self.rsbox[col+16*(row)] )
        return out
            
        
    def invShiftRows( self, block ): # Spostamento dei byte di un certo numero di posizioni dipendente dalla riga di appartenenza.
        out = [ block[0], block[13], block[10], block[7], 
                block[4], block[1], block[14], block[11], 
                block[8], block[5], block[2], block[15], 
                block[12], block[9], block[6], block[3] ]
        return out   
        
        
    def invMixColumns( self, block ): # Combinazione dei byte con un'operazione lineare, i byte vengono trattati una colonna per volta.
        out = [0] * self.nb * 4
        for i in range( 0, self.nb ):
            for j in range ( 0, self.nb ):
                for k in range( 0, self.nb ):
                    out[j+i*self.nb] = int( self.byteXor( out[j+i*self.nb], self.polyMult( self.rmix_matrix[k+j*self.nb], block[k+i*self.nb] ) ), 16 )
                out[j+i*self.nb] = hex( out[j+i*self.nb] )
        return out
        
        
    def keyExpansion( self, key ): # Expand the key in order to generate an initialization vector for the 10 rounds 
        out = [['0x00', '0x00', '0x00', '0x00']] * self.nb*(self.nr+1)
        out[0] = key[:8]
        out[1] = key[8:16]
        out[2] = key[16:24]
        out[3] = key[24:]
        
        for i in range( 0, 4 ):
            sub = []
            for j in range( 0, len(out[i]), 2 ):
                sub.append( hex( int( out[i][j:j+2], 16 ) ) )
            out[i] = sub
        
        for i in range( self.nk, self.nb*(self.nr+1) ):
            temp = out[i-1]
            if(i % self.nk == 0):
                temp = self.xor( self.subWord( self.rotWord( temp ) ), self.rCon[(i//self.nk)-1] )
            elif( self.nk > 6 and i % self.nk == 4):
                temp = self.subWord( temp )
            out[i] = self.xor( out[i-self.nk], temp )
        return out
            
            
    def subWord( self, block ): # Sostituzione non lineare di tutti i byte che vengono rimpiazzati secondo una specifica tabella.
        out = []
        for i in block:
            if( len( i ) == 3 ):
                row = 0
            else:
                row = int( i[2], 16 )
            if( len( i ) == 3 ):
                col = int( i[2], 16 )
            else:
                col = int( i[3], 16 )
            out.append( hex( self.sbox[col+16*(row)] ) )
        return out
        
        
    def rotWord( self, block ):
        out = [0] * 4
        temp = block[0]
        for i in range( 1, 4 ):
            out[i-1] = block[i]
        out[3] = temp
        return out
        
        
    def polyMult( self, a, b ):
        p = 0
        for counter in range(8):
            if b & 1: p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            a &= 0xFF
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p
        
       
    def incrementCounter( self ):
        i = 15
        while( int( self.iv[i], 16 ) == 255 ):
            self.iv[i] = hex( 0 )
            i-= 1
        self.iv[i] = hex( int( self.iv[i], 16 ) + 1 )      

 
    def xor( self, w1, w2 ):
        out = []
        for i in range( 0, len( w1 ) ):
            out.append( self.byteXor( int( w1[i], 16), int( w2[i], 16) ) )
        return out
        
        
    def byteXor( self, s1, s2 ):
        return hex( s1 ^ s2 )
        
    
    def setIv( self, iv ):
        self.iv = self.splitKey( iv )
       
        
    def setPlaintext( self, plaintext ):
        self.splitted = self.splitText( plaintext )
        
        
    def setCiphertext( self, ciphertext ):
        self.ciphertext = self.splitText( ciphertext )
        
        
    def getCiphertext( self ):
        print( "IV: ", "".join( self.convertHex( self.iv ) ) )
        print( "Key: ", "".join( self.convertHex( self.key ) ) )
        ciphertext = []
        for i in self.ciphertext:
            ciphertext.append( self.convertHex( i ) )
        print( "Ciphertext: ", "".join( map( "".join, ciphertext ) ) )
        
        
    def getPlaintext( self ):
        print( "IV: ", "".join( self.convertHex( self.iv ) ) )
        print( "Key: ", "".join( self.convertHex( self.key ) ) )
        splitted = []
        for i in self.splitted:
            splitted.append( self.convertHex( i ) )
        print( "Plaintext: ", "".join( map( "".join, splitted ) ) )
 
 
    def convertHex( self, block ):
        out = []
        for i in block:
            c = i.replace( "0x", "" )
            if( len( c ) < 2 ):
                out.append( "0" + c )
            else:
                out.append( c )
        return out