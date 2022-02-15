from tkinter import *
from tkinter import messagebox
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import os
import os.path
import binascii
import rsa
from os import listdir
from os.path import isfile, join
from secrets import token_bytes
import time

root = Tk()
root.geometry("2000x400") #width and height
root.title("Python Cryptography Tool")


myLabel = Label(root,text="Python Cryptography Processor", underline=0)

#create direction/instructional labels
myLabel = Label(root, text="Python Cryptography Processor - Ethan Couch", padx = 40, pady = 20)
myLabel1 = Label(root, text="Input plaintext/ciphertext - AES:", padx = 40, pady = 20)
myLabel2 = Label(root, text="Input plaintext/ciphertext - RSA:", padx = 40, pady = 20)
myLabel3 = Label(root, text="Input plaintext for digital signature:", padx = 40, pady = 20)
myLabel4 = Label(root, text="Input a message+signature for verification:", padx = 40, pady = 20)
myLabel5 = Label(root, text="Input plaintext for SHA256 hash computation:", padx = 40, pady = 20)

#assign instruction labels to grid structure
myLabel.grid(row=0, column=2)
myLabel1.grid(row=1, column=0)
myLabel2.grid(row=3, column=0)
myLabel3.grid(row=5, column=0)
myLabel4.grid(row=7, column=0)
myLabel5.grid(row=9, column=0)

#function results/output labels
myLabel1OutputEncrypt = Label(root, text="Encrypted Ciphertext:", padx = 40, pady = 20)
myLabel1OutputDecrypt = Label(root, text="Decrypted Plaintext:", padx = 40, pady = 20)
myLabel2OutputEncrypt = Label(root, text="Encrypted Ciphertext:", padx = 40, pady = 20)
myLabel2OutputDecrypt = Label(root, text="Decrypted Plaintext:", padx = 40, pady = 20)
myLabelOutputSignature = Label(root, text="Signature:")
myLabelOutputVerification = Label(root, text="Verification Result:", padx = 40, pady = 20)
myLabelOutputHash = Label(root, text="SHA256 Hash:", padx = 40, pady = 20)

#implement output labels amidst grid structure
myLabel1OutputEncrypt.grid(row=1, column=3)
myLabel1OutputDecrypt.grid(row=1, column=4)
myLabel2OutputEncrypt.grid(row=3, column=3)
myLabel2OutputDecrypt.grid(row=3, column=4)
myLabelOutputSignature.grid(row=5, column=3)
myLabelOutputVerification.grid(row=7, column=5)
myLabelOutputHash.grid(row=9, column=3)

textboxPlaintextCiphertextAES = Entry(root, width=50)
#plainTextAES = textboxPlaintextAES.get()
#textboxPlaintextAES.pack()
#textboxPlaintextAES.insert(0,"Input plaintext - AES:\n")

#textboxCiphertextAES = Entry(root, width=50)
#textboxCiphertextAES.pack()
#textboxCiphertextAES.insert(0,"Input ciphertext - AES:\n")

textboxPlaintextCiphertextRSA = Entry(root, width=50)
#textboxPlaintextRSA.pack()
#textboxPlaintextRSA.insert(0,"Input plaintext - RSA:\n")

#textboxCiphertextRSA = Entry(root, width=50)
#textboxCiphertextRSA.pack()
#textboxCiphertextRSA.insert(0,"Input ciphertext - RSA:\n")

textboxSig = Entry(root, width=50)
#textboxSig.pack()
#textboxSig.insert(0,"Input plaintext for digital signature:\n")

textboxVerificationMessage = Entry(root, width=50)
#textboxVerification.pack()
#textboxVerificationMessage.insert(0,"Input message for verification:")

textboxVerificationSignature = Entry(root, width=50)
#textboxVerificationSignature.insert(0,"Input signature for verification:")

textboxHash = Entry(root, width=50)
#textboxHash.pack()
#textboxHash.insert(0,"Input plaintext for SHA256 hash computation:\n")

textboxPlaintextCiphertextAES.grid(row=1, column=1)
#textboxCiphertextAES.grid(row=1, column=3)
textboxPlaintextCiphertextRSA.grid(row=3, column=1)
#textboxCiphertextRSA.grid(row=3, column=3)
textboxSig.grid(row=5, column=1)
textboxVerificationMessage.grid(row=7, column=1)
textboxVerificationSignature.grid(row= 7, column=2)
textboxHash.grid(row=9, column=1)


"""class AESEncryptor:  #CBC_MODE AES ENCRYPTION/DECRYPTION VERSION 1

    def __init__(self, key): #function that initializes the key
        self.key = key

    def padFunct(self,string):
        return string+b"" * (AES.block_size - len(string) % AES.block_size)

    def EncryptAES(self, message, key, key_size = 256):
        plaintextAES = textboxPlaintextAES.get()
        message = self.padFunct(plaintextAES)
        iv = Random.new().read(AES.block_size)
        encryptedTextAES = AES.new(key, AES.MODE_CBC, iv) #here we use the AES module of the pyCrypto library to invoke a CipherBlockChaining mode
        myLabel1OutputEncrypt['text'] = encryptedTextAES
        return plaintextAES + encryptedTextAES.encrypt(message)

    def DecryptAES(self, ciphertextAES, key):
        ciphertextAES = textboxCiphertextAES.get() 
        iv = #setting iv
        encryptedTextAES = AES.new(key, AES.MODE_CBC, ciphertextAES)
        plaintext = encryptedTextAES.decrypt(ciphertextAES)
        myLabel1OutputDecrypt['text'] = plaintext.rstrip(b"\0") #rstrip makes decrypted text a multiple of block size of cipher
        return plaintext.rstrip(b"\0")

key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e' #initialize key here
"""

""" #ATTEMPTED ENCRYPTION/DECRYPTION USING EAX-MODE AES BELOW
keyAES = token_bytes(16) #here, we are importing a the token_bytes function from the secret module to generate a randomkey
#cipher = AES.new(keyAES, AES.MODE_EAX)
#nonce = cipher.nonce
#plainTextAES = textboxPlaintextAES.get()
#ciphertext,tag = cipher.encrypt_and_digest(plainTextAES.encode('ascii'))
#myLabel1OutputEncrypt['text'] = {ciphertext}

def EncryptAES():
    #key = b'Sixteen byte keySixteen byte key'
   
    cipher = AES.new(keyAES, AES.MODE_EAX)  #we will use EAX encryption, a less advanced form of AES that does not employ a nonce
    nonce = cipher.nonce
    plainTextAES = textboxPlaintextAES.get()
    print(f'The message is: {plainTextAES}')
    ciphertext,tag = cipher.encrypt_and_digest(plainTextAES.encode('ascii'))
    print(f'The ciphertext is: {ciphertext}')
   
    myLabel1OutputEncrypt['text'] = {ciphertext}
    textboxPlaintextAES.delete(0, END)

    print(f'The tag is: {tag}')
    return nonce, ciphertext, tag
    

#print(f'The nonce is: {nonce}')
#print(f'The ciphertext is: {ciphertext}')
#print(f'The tag is: {tag}')
nonce,ciphertext, tag = EncryptAES()
print(f'(Returned-The nonce is: {nonce}')
print(f'Returned-The ciphertext is: {ciphertext}')
print(f'Returned-The tag is: {tag}')


def DecryptAES():
    #key = b'Sixteen byte keySixteen byte key'
    #cipher = AES.new(keyAES, AES.MODE_EAX, nonce=nonce)
    cipher = AES.new(keyAES, AES.MODE_EAX, nonce=nonce)
    cipherTextAES = textboxCiphertextAES.get()
    print(f'The ciphertextAES is: {cipherTextAES}')
    print(f'the value of ciphertext is: {ciphertext}')
    plaintext = cipher.decrypt(ciphertext)
    print(f'The plaintext is: {plaintext}')
    #decryptedPlaintext = plaintext.decode('ascii')
    #myLabel1OutputDecrypt['text'] = decryptedPlaintext
    decryptedPlaintext = plaintext.decode('ascii')
    myLabel1OutputDecrypt['text'] = textboxPlaintextAES.get()
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except ValueError:
        print("Key incorrect or message corrupted")

#nonce,ciphertext, tag = EncryptAES()
#plaintext = DecryptAES()
"""

#inputs
plaintext = "testlakjdfkjdlksjf"
AESkey = pad(b"mykey",AES.block_size)
initVector = pad(b"myiv",AES.block_size)

def  EncryptDecryptAES(plaintext):
    if plaintext == "":
        messagebox.showerror('No input detected', "Please enter plaintext/ciphertext into the field before clicking the button")
    else:
        data_btyes = bytes(plaintext,'utf-8') #need to convert plaaintext to utf-8 encoded format to encrypt
        padded_bytes = pad(data_btyes, AES.block_size) #next, we need to pad the data bytes to appease the mode specifications
        AES_obj = AES.new(AESkey, AES.MODE_CBC,initVector) # here, we initialize an AES object as a catalyst to be used later
        ciphertext = AES_obj.encrypt(padded_bytes) #finally, we use the previously defined AES object to call the encrypt method on the padded bytes, to get our ciphertext
        print(' \nAES ALGORITHM OUTPUT:\n')
        print(' ENCRYPTION')
        print(f'Plaintext before encryption: {plaintext}')
        print(f'databytes: {data_btyes}')
        print(f'Ciphertext after padding and encryption: {ciphertext}')
        print(f'Ciphertext with binascii hexformatting is: {binascii.hexlify(ciphertext)}\n')
    #myLabel1OutputEncrypt['text'] = binascii.hexlify(ciphertext) #here, i choose to convert the ciphertext to a cleaner hex format using binascii.hexlify() 
        myLabel1OutputEncrypt['text'] = messagebox.showinfo(f'AES Encryption of {plaintext}', binascii.hexlify(ciphertext))
        myLabel1OutputEncrypt['text'] = binascii.hexlify(ciphertext)
#decrypt here
        print(' DECRYPTION')
        AES_obj= AES.new(AESkey,AES.MODE_CBC,initVector)
        print(f'Ciphertext before decryption: {ciphertext}')

        raw_btyes = AES_obj.decrypt(ciphertext)
        print(f' Ciphertext after CBC decryption: {raw_btyes}')
        extracted_bytes=unpad(raw_btyes,AES.block_size)
        plaintext = extracted_bytes.decode('ascii')
        print(f'Ciphertext after CBC decryption and unpadding: {extracted_bytes}')
    #myLabel1OutputDecrypt['text'] = extracted_bytes
        myLabel1OutputDecrypt['text'] = messagebox.showinfo(f'AES Decryption of {ciphertext}', extracted_bytes)
        myLabel1OutputDecrypt['text'] = extracted_bytes
        textboxPlaintextCiphertextAES.delete(0, END)
    return ciphertext


""""
def DecryptAES(ciphertext):
    data_bytes = bytes(ciphertext,'utf-8')
    AES_obj= AES.new(AESkey,AES.MODE_CBC,initVector)
    #data_btyes = bytes(ciphertext,'ascii')
    raw_btyes = AES_obj.decrypt(data_bytes)
    extracted_bytes=unpad(raw_btyes,AES.block_size)
    extracted_bytes.decode('ascii')
    #print(f'value of extractbytes: {extracted_bytes}')
    myLabel1OutputDecrypt['text'] = extracted_bytes#.decode('ascii')
    return extracted_bytes
#plaintext = DecryptAES(ciphertext) #sets plaintext thats outputted in label to the extracted bytes decoded of decrypt method
"""
#RSA Public Key Cryptography Algorithm

publicKey, privateKey = rsa.newkeys(256) #first generate public and private keys of 512 bits. done by using newkeys method which accepts keylength n as param
def EncryptDecryptRSA():
    plaintextRSA = textboxPlaintextCiphertextRSA.get()
    if plaintextRSA == "":
        messagebox.showerror('No input detected', "Please enter plaintext/ciphertext into the field before clicking the button")
    else:
    #first generate public and private keys of 512 bits. done by using newkeys method which accepts keylength n as param
     #sets  plaintext message to by encrypted; captured by textboxentry on gui
    #encryption begins: asymettric public key algorithm is simulated using rsa module's encrypt function to encrypt plaintext string with public key string, once the plaintext is encoded
        ciphertextRSA = rsa.encrypt(plaintextRSA.encode(),publicKey) #default encoding utf-8
        print('\n RSA ALGORITHM OUTPUT:\n')
        print('ENCRYPTION')
        print(f'Plaintext before encryption: {plaintextRSA}')
        print(f'Ciphertext after message encoding and encryption with public key: {ciphertextRSA}')
        print(f'Ciphertext (hex-formatted): {binascii.hexlify(ciphertextRSA)}\n')
    
        myLabel2OutputEncrypt['text'] = messagebox.showinfo(f'RSA Encryption of {plaintextRSA}', binascii.hexlify(ciphertextRSA))
        myLabel2OutputEncrypt['text'] = binascii.hexlify(ciphertextRSA)
    
    
        decryptedPlaintextRSA = rsa.decrypt(ciphertextRSA,privateKey).decode()

        myLabel2OutputDecrypt['text'] = messagebox.showinfo(f'RSA Decryption of {ciphertextRSA}', decryptedPlaintextRSA)
        myLabel2OutputDecrypt['text'] = decryptedPlaintextRSA
        print('DECRYPTION')
        print(f'the value of decoded  ciphertext, decrypted using private key : {decryptedPlaintextRSA}')
        textboxPlaintextCiphertextRSA.delete(0, END)

    return ciphertextRSA

"""def EncryptRSA():
   ## publicKey, privateKey = rsa.newkeys(256) #first generate public and private keys of 512 bits. done by using newkeys method which accepts keylength n as param
    plaintextRSA = textboxPlaintextRSA.get() #sets  plaintext message to by encrypted; captured by textboxentry on gui
    #encryption begins: asymettric public key algorithm is simulated using rsa module's encrypt function to encrypt plaintext string with public key string, once the plaintext is encoded
    ciphertextRSA = rsa.encrypt(plaintextRSA.encode(),publicKey) #default encoding utf-8
     
    print(f'Plaintext before encryption: {plaintextRSA}')
    print(f'Ciphertext after message encoding and encryption with public key: {ciphertextRSA}')
    print(f'the value of ascii hex-formatted ciphertext is: {binascii.hexlify(ciphertextRSA)}')
    
    myLabel2OutputEncrypt['text'] = binascii.hexlify(ciphertextRSA)
    return ciphertextRSA    
"""
"""
def DecryptRSA():
    entryCiphertext = textboxCiphertextRSA.get()
    byteconvert = bytes(entryCiphertext, 'utf-8')
    ciphertextRSA = rsa.encrypt(byteconvert, publicKey)
    print(f'Encrypted ciphertext before decryption method: {ciphertextRSA}')
    plaintextRSA = rsa.decrypt(ciphertextRSA, privateKey).decode()
    print(f'Decrypted ciphertext from decryption method: {plaintextRSA}')
    myLabel2OutputDecrypt['text'] = {ciphertextRSA}                                #output to label 
    textboxCiphertextRSA.delete(0, END)
    return
"""

#Plaintext to Digital Signature Algorithm
#using RSA to create signature
sigKey = RSA.generate(1024)
public_key = b''
private_key =b''
origMessage = b'original' 
origSignature = b'p\xb8S?]\xe1J\x16\xb5\xf0\xee\xa3p\xd8\xc0D\xb0\x81\x9734\x86\xabf\x85\xbb\x08\xbfr\xaf\x98\xcb-\x02\'\x1d\t\x1fy8g\x18\x1e2\xc5\x96F\x9cA\x0ce\x93\x94\x128\x01\xce\x92\xa5) g\xf7H\x8ar?\xf8ME\xa9\xf8\x9f 9tDz\x04\xbf\xed\xce5\x0c\xf2\x01\x8f\x07"\xdc\x1f\xbdgv\xb4P\xf7X\x81\xa0\xb6\x1c\xda\xd1\xc8\xe7>\n}\xdf,\xbcLQ\xfa\xec\x81?8\xdd\xfc$\xed\x958\x04yR'
origSignature = binascii.hexlify(origSignature)

#print(f'\nVALUE (hexascii) OF PRESET HIDDEN SIGNATURE of MESSAGE original: {origSignature}\n')
def generatePrivateKeys():
    print('\nPrivate Key Generation Executed.\n')
    global sigKey
    #sigKey = RSA.generate(1024)
    global private_key 
    private_key = sigKey.export_key() 
    #print(f'Private key data: {private_key}')
    #print('\n')
    #global public_key
    #public_key = sigKey.public_key().export_key()
    #print(f'Public key data: {public_key}')
    
    return private_key

def generatePublicKeys():
    print('\nPublic Key Generation Executed.\n')
    global sigKey
    #sigKey = RSA.generate(1024)
    #global private_key 
    #private_key = sigKey.export_key() 
    #print(f'Private key data: {private_key}')
    #print('\n')
    global public_key
    public_key = sigKey.public_key().export_key()
    #print(f'Public key data: {public_key}')
    
    return public_key

def getSignature():
    #sigKey = RSA.generate(1024) #generated key for the signing algorithm
    print('\n SIGNING ALGORITHM OUTPUT:\n')
    #testString = "testtesttest"
    generatePrivateKeys()
    print(f'Private key data: {private_key}')
    print('\n')
    plaintextS = textboxSig.get()
    if  plaintextS == "":
        messagebox.showerror('No input detected', "Please enter plaintext into the field before clicking the button")
    else:
        byteconvert = bytes(plaintextS, 'utf-8') #convert user input to bytes
        print(f'Plaintext before signing: {byteconvert} \n')

        """##Generating and exporting private/public_key
        private_key = sigKey.export_key() 
        print(f'Private key data: {private_key}')
        print('\n')
        global public_key
        public_key = sigKey.public_key().export_key()
        print(f'Public key data: {public_key}')
        print('\n')
        """
        #Sign the plaintext by hashing it, and then using an imported private key to create a singing object that signs the hash
        sigKey = RSA.import_key(private_key)
        hashedUserInput = SHA256.new(byteconvert) #create hash of the inputted plaintext
        #print(f'value of hashedUserInput: {hashedUserInput}\n')
    #Sign the original message using original hash
        global origMessage #global message variable accompanied by hash to be compared to for verification
        global origSignature #global original signature to compare to newly generated hash               
        #global originalMessageConverted = bytes(originalMessage, 'utf-8')
        #origHash = SHA256.new(origMessage)
        #print(f'value of OrigMessage Before Hash Calculation within Signing algo: {origMessage}\n')
        #print(f'value of OriginalHash: {origHash}\n')
        
        signingObject = pkcs1_15.new(sigKey) #create object that will be used to sign the message; uses our private key
        digSignature = signingObject.sign(hashedUserInput)  #once we create a hash of the message, we can create its digital signature
        print(f'Digital Signature: {digSignature}\n') # message to be signed is first hashed to produce a short digest then signed by a trapdoor permutation such as the RSA function.
        #origSignature = signingObject.sign(origHash) #here, I set the original signature that will be used to compare to any new hash
        #print(f'\nOriginal Signature Value Created on origHash, within Signature Algo: {origSignature}\n')
    #A trapdoor permutation being something that is easy to compute in the forward direction, but is difficult to compute in the reverse direction without already knowing the private key, or 'trapdoor'.
    # I decide to use a Trapdoor permutation through RSA for the signing algorithm - computing the reverse direction with the secret key is required for signing, and computing the forward direction is used to verify signatures.
        print(f'Digital Signature (hexadecimal converted): {binascii.hexlify(digSignature)}')
        textboxSig.delete(0, END)
        myLabelOutputSignature['text'] = messagebox.showinfo(f'Digital Signature of {plaintextS}', binascii.hexlify(digSignature))
        #myLabelOutputSignature['text'] = binascii.hexlify(digSignature)                                    #output to label 
    return

#MessageSignature Verification Algorithm - after sending signature + message to another person, they would now have to verify if the message is original- this requires use of mr signature

def getVerification():
    generatePublicKeys()
    #print(f' key data: {public_key}')
    
    #sigKey = RSA.generate(1024)
    print('\n VERIFICATION ALGORITHM OUTPUT:\n')
    #plaintextS = textboxSig.get()
    #byteconvert = bytes(plaintextS, 'utf-8') #convert user input to bytes
    #print(f'Plaintext before signing: {byteconvert} \n')

    ##Generating and exporting private/public_key
   # private_key = sigKey.export_key() 
    #print(f'Private key data: {private_key}')
    #print('\n')

    #public_key = sigKey.public_key().export_key()
    #print(f'Public key data: {public_key}')
    #print('\n')

    #Sign the plaintext
    #sigKey = RSA.import_key(private_key)
    #hashToBeSigned = SHA256.new(byteconvert)
    
    global origMessage #global message variable accompanied by hash to be compared to for verification
    global origSignature #global original signature to compare to newly generated hash    
    #signingObject = pkcs1_15.new(sigKey) 
    #digSignature = signingObject.sign(hashToBeSigned) 
    #print(f'Digital Signature: {digSignature}') 
    
   
    #Verification starts here
    #print(f'\n    VERIFICATION ALGORITHM:\n')
    
    sigKey = RSA.import_key(public_key) #For verification, we use the public key
    print(f'value of imported public key: {public_key}\n')
    
    verifiableMessage = textboxVerificationMessage.get()
    verifiableSignature = textboxVerificationSignature.get()
    if  verifiableMessage == "" or verifiableSignature == "":
        messagebox.showerror('Incomplete signatured message', "Please enter both a message and a signature before attempting verification")
    else:
        byteconvert2 = bytes(verifiableMessage, 'utf-8')
        #print(f'\nMessage Entered for Verification: {byteconvert2}\n')
        #print(f'\n userInput: {byteconvert}')   #prints value of userinput before it was signed (algorithm 3)
        #global origMessage
        #print(f'Value of original (hidden) message: {origMessage}\n')
        print(f'Value of received (comparison) signature: {origSignature}')
        #originalSignedMessage = origMessage+ binascii.hexlify(origSignature)
        originalSignedMessage = origMessage+origSignature
        #print(f'\nOriginal Message with Original signature: {originalSignedMessage}\n')
        #verifiableSignature = textboxVerificationSignature.get() 
    #if  verifiableSignature == "":
        #messagebox.showerror('Incomplete signatured message', "Please enter both a message and a signature before attempting verification")
    #else:
        byteconvert3 = bytes(verifiableSignature, 'utf-8')
        print(f'\nMessage Entered for Verification: {byteconvert2}\n')
        print(f'Signature Entered for Verification: {byteconvert3}')
        inputtedSignedMessage = byteconvert2+byteconvert3
        print(f'\nMessage with Digital signature: {inputtedSignedMessage}\n')
      
        #set entered message to new origMessage  
       # origMessage = byteconvert2
        #print(f'NEW ASSIGNED VALUE OF origMESSAGE after equating it to user input: {origMessage}\n')
        #hashReceived = SHA256.new(byteconvert2)  ##uncomment for the try/except implementation below that uses pkcs1_15 module's verify       #hash the new message; compare this hash to the original hash(the sent message)
        #print(f'value of hash of entered message: {hashReceived}')
        #textboxVerificationMessage.delete(0, END)
        #textboxVerificationSignature.delete(0, END)
    #verification command
        #try:
            #pkcs1_15.new(sigKey).verify(hashReceived, origSignature)
            #print("The received signature is valid, and the message has not been changed.")
            #myLabelOutputVerification['text'] = messagebox.showinfo(f'Verification Result of {byteconvert2+byteconvert3}', 'Valid')
            #myLabelOutputVerification['text'] = 'The received signature is valid, and the message has not been changed.'
        #except (ValueError, TypeError):
            #print ("The message has been altered.")
            #myLabelOutputVerification['text'] = messagebox.showinfo(f'Verification Result of {byteconvert2+byteconvert3}', 'Invalid')
            #myLabelOutputVerification['text'] = 'The hash of the input message differs from original. The message has been altered from the original.'
    if originalSignedMessage == inputtedSignedMessage:
        print("The received signature is valid, and the message has not been changed.")
        myLabelOutputVerification['text'] = messagebox.showinfo(f'Verification Result of {byteconvert2+byteconvert3}', 'Valid - the hash has not been altered from original')
        myLabelOutputVerification['text'] = 'The received signed message is valid; the hash has not been altered from original.'
    else: 
        print ("The message has been altered.")
        myLabelOutputVerification['text'] = messagebox.showinfo(f'Verification Result of {byteconvert2+byteconvert3}', 'Invalid - the message has been altered from the original')
        myLabelOutputVerification['text'] = 'The hash of the input message+signature differs from original. The message has been altered from the original.'
    textboxVerificationMessage.delete(0, END)
    textboxVerificationSignature.delete(0, END)
    return
#print(f'\nPRINTING VALUE OF GLOBAL SIGNATURE VALUE AFTER VERIFICATION METHOD ENDS: {origSignature}')


#Hash Algorithm: Plaintext to SHA256 Hash Computation

def getHash():
    plaintextH = textboxHash.get()
    if  plaintextH == "":
        messagebox.showerror('No plaintext entered', "Please enter plaintext before attempting SHA256 hash computation")
    else:
        print(' \nHASHING ALGORITHM OUTPUT:\n')
        print(f'Plaintext before Hashing: {plaintextH}')
        hashed_output = hashlib.sha256(plaintextH.encode('ascii')).hexdigest()
        print(f'SHA256 hash: {hashed_output}')
        myLabelOutputHash['text'] = messagebox.showinfo(f'SHA256 Hash of {plaintextH}', hashed_output)
        myLabelOutputHash['text'] = hashed_output
        textboxHash.delete(0, END)
    return

def popup():
    messagebox.showinfo('Received Message',"The message 'original' is in need of verification")








#Buttons and click commands

#buttonEncryptAES = Button(root, text="Encrypt AES", padx = 33, pady = 10, width = 30, command= lambda: EncryptAES(textboxPlaintextAES.get()))
buttonEncryptDecryptAES = Button(root, text="Encrypt/Decrypt AES", padx = 33, pady = 10, width = 30, command= lambda: EncryptDecryptAES(textboxPlaintextCiphertextAES.get()))
#buttonDecryptAES = Button(root, text="Decrypt AES", padx = 33, pady = 10, width = 30, command = lambda: DecryptAES(ciphertext))
#buttonDecryptAES = Button(root, text="Decrypt AES", padx = 33, pady = 10, width = 30, command = lambda: DecryptAES(bytes(textboxCiphertextAES.get(), 'utf-8')))
#buttonDecryptAES = Button(root, text="Decrypt AES", padx = 33, pady = 10, width = 30, command = lambda: DecryptAES(textboxCiphertextAES.get()))

#buttonEncryptAES = Button(root, text="Encrypt AES", padx = 33, pady = 10, width = 30, command= EncryptAES)
#buttonDecryptAES = Button(root, text="Decrypt AES", padx = 33, pady = 10, width = 30, command = myLabel1OutputDecrypt.grid(row=1, column=6))

buttonEncryptDecryptRSA = Button(root, text="Encrypt/Decrypt RSA", padx = 33, pady = 10, width = 30, command = EncryptDecryptRSA)
#buttonDecryptRSA = Button(root, text = "Decrypt RSA", padx = 33, pady = 10, width = 30, command = DecryptRSA)

buttonGetSignature = Button(root, text = "Output Signature", padx = 33, pady = 10, width = 30, command = getSignature)

#buttonGetVerification = Button(root, text = "Output Verification Result", padx = 33, pady = 10,  width = 30, command = getVerification)
buttonGetVerification = Button(root, text = "Output Verification Result", padx = 33, pady = 10,  width = 30, command = getVerification)

buttonGetHash = Button(root, text = "Output SHA256 Hash", padx = 33, pady = 10, width = 30, command = getHash)

popupButton = Button(root, text = "View received message", command =popup)

#Add buttons to grid structure 
buttonEncryptDecryptAES.grid(row=1, column=2)
#buttonDecryptAES.grid(row=1, column=4)
buttonEncryptDecryptRSA.grid(row=3, column=2)
#buttonDecryptRSA.grid(row=3, column=4)
buttonGetSignature.grid(row=5, column=2)
buttonGetVerification.grid(row=7, column=4)
buttonGetHash.grid(row=9, column=2)
popupButton.grid(row = 7, column=3)


root.mainloop()
