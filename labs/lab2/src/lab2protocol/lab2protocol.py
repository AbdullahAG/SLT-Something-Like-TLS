from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from playground.common import Timer, Seconds
from playground.network.packet import PacketType, FIELD_NOT_SET
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.packet.fieldtypes import UINT8, UINT32, BUFFER, STRING, LIST
#-----key-------------
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKeyWithSerialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
#------Hash-----------
from hashlib import sha256
#---------------------
import asyncio
import pem
import hashlib
import random
import random as rand
from random import randint
import sys
import datetime


#packet creation
class SITHPacket(PacketType):
	DEFINITION_IDENTIFIER = "SITH.kandarp.packet"
	DEFINITION_VERSION = "1.0"

	FIELDS = [
		("Type", STRING),
		("Random", BUFFER({Optional: True})),
		("PublicValue", BUFFER({Optional: True})),
		("Certificate", LIST(BUFFER)({Optional: True})),
		("Signature", BUFFER({Optional: True})),
		("Ciphertext", BUFFER({Optional: True}))
		]


#----------end class------------

class SITH(StackingProtocol):
	def __init__(self):
		super().__init__()
		self.transport = None
		self.SITHtransport = None
		self.stateCon = 0 # 0 = start, 1 = first hello sent, 2 = ongoing - data, 3 = cloes
		#random number generating------------------------------
		rand.seed()
		self.randomNumber = str(rand.getrandbits(256)).encode()
		#------------------------------------------------------
		self.CRL = [] #blacklist
		self.otherSideRand = None #the random number of the other side
		self.sharedSecret = None #other side public key and this side private key
		self.sharedPacketSecret = None #hash of both this side hello and the other side hello
		self.hello = None #hello message packet
		self.otherSideHello = None #the other side hello packet
		self.the_iv = None # the iv
		self.write_key = None #wite key
		self.read_key = None #read key
		self.certlist = None
		self.root_serial = 89894
		#----key generating-----------------------------
		# Generate a private key for use in the exchange.curvex25519
		self.private_key = X25519PrivateKey.generate()
		# Generate a public key for use from the private key curvex25519
		self.public_key = self.private_key.public_key()
		#-----generating the certificate-----------------
		in_file = open("80085csr_signed.cert", "rb") # opening for [r]eading as [b]inary
		self.cert_inter = in_file.read() # if you only wanted to read 512 bytes, do .read(512)
		in_file_root = open("20184_root_signed.cert", "rb")
		self.cert_root = in_file_root.read()
		self.certlist = ([self.cert_inter, self.cert_root])
		#------Private key sign--------------------------
		in_file_key = open("eckey.pem", "rb") # opening for [r]eading as [b]inary
		self.key_data = in_file_key.read() # if you only wanted to read 512 bytes, do .read(512)
		#------------------------------------------------
		#------Public key sign--------------------------
		in_file_pkey = open("ecpubkey.pem", "rb") # opening for [r]eading as [b]inary
		self.pkey_data = in_file_pkey.read() # if you only wanted to read 512 bytes, do .read(512)
		#------------------------------------------------
		self._deserializer = SITHPacket.Deserializer()


		
	def datecheck(self,rcerts):
		for cert in rcerts:
			now = datetime.datetime.now()
			if(not cert.not_valid_before<now):
				return False
			if(not cert.not_valid_after>=now):
				return False
		return True

		
	def RootcheckCerts(self, recieved_certs):
		rcerts=[]
		trustlist={}
		in_file_root = open("20184_root_signed.cert", "rb")
		data_root = in_file_root.read()
		cert_obj_root = x509.load_pem_x509_certificate(data_root, default_backend())
		issuer = cert_obj_root.issuer		

		for rcert in recieved_certs:
			rcert_obj = x509.load_pem_x509_certificate(rcert, default_backend())
			if(rcert_obj.serial_number != cert_obj_root.serial_number):
					rcerts.append(rcert_obj)
					trustlist={str(rcert_obj.serial_number):'False'}
		if(self.datecheck(rcerts)):
			if(self.cehckwithCRL(rcerts)):


			
				allfound = False
				i=0
				cert_check = cert_obj_root
				while(not allfound):
					print(i)
					rcert = rcerts[i]
					if(rcert.issuer == issuer):
						try:
							print('I am trying to verify')
							cert_check.public_key().verify(rcert.signature, rcert.tbs_certificate_bytes,ec.ECDSA(rcert.signature_hash_algorithm))
							trustlist[str(rcert.serial_number)]= 'True'
							print('I verified')
						except:
							print("OH NO - we gotta blacklist this")
							self.CRL.append(rcert.serial_number)
							self.connection_lost()
							return
						issuer = rcert.subject
						cert_check = rcert
						if('False' in trustlist.values()):
							if(i+1<len(trustlist)):
								i+=1
							else:
								i=0
						else:
							allfound = True
					else:
						if(i+1 < len(trustlist)):
							i+=1
						else:
							break
				print(trustlist)
				if(allfound):
					return True
				else:
					return False
		
			else:
				print("cert found in CRL....quitting")
				return False
		else:
			print("cert failed date check....quitting")
			return False


	def connection_lost(self, exc):
		error_msg = exc.encode()
		self.sendShutdown(error_msg)
		print("close connection because ,,, {} ,,,".format(exc))
		self.higherProtocol().connection_lost(exc)

	
	def sendHello(self):
		helloPacket = SITHPacket(Type = "HELLO", Random = self.randomNumber, PublicValue = self.public_key.public_bytes(), Certificate = self.certlist)
		print("send a Hello packet: Random number = {}".format(self.randomNumber))
		self.hello = helloPacket.__serialize__()
		self.transport.write(self.hello)


	def sendFinish(self):
		print("im sending a finish packet")
		finish_load = self.otherSideHello
		loaded_private_key = serialization.load_pem_private_key(
		self.key_data, password = None, backend=default_backend())
		signature = loaded_private_key.sign(finish_load,ec.ECDSA(hashes.SHA256()))
		finishPacket = SITHPacket(Type = "FINISH", Signature = signature)
		self.transport.write(finishPacket.__serialize__())
	
	
	def checkFinish(self, sig):
		print("check signature...")
		loaded_public_key = serialization.load_pem_public_key(self.pkey_data, backend=default_backend())
		loaded_public_key.verify(sig, self.hello, ec.ECDSA(hashes.SHA256()))
		print("the signature is correct\n continue")
		
		
	def cehckwithCRL(self, recieved_certs):
		for cert in recieved_certs:
			if(cert.serial_number in self.CRL):
				return False
		return True
		
		
	def sendDataDown(self, dat):
		enDataPacket = SITHPacket(Type = "DATA", Ciphertext = dat)
		self.transport.write(enDataPacket.__serialize__())
		
		
	def sendShutdown(self, error_msg):
		en_data = self.AEAD_encrypt(error_msg)
		closePacket = SITHPacket(Type = "CLOSE", Ciphertext = en_data)
		self.transport.write(closePacket.__serialize__())

		
		
#----------end class------------
class SithClientProtocol(SITH):

	def connection_made(self, transport):
		print("Received a connection from SITH server")
		self.transport = transport
		self.SITHtransport =  ATPtransport(self.transport, self)
		#-----generating the server certificate-----------------
		in_file = open("80085_1_signed.cert", "rb") # opening for [r]eading as [b]inary
		data_leaf = in_file.read() # if you only wanted to read 512 bytes, do .read(512)
		self.certlist.append(data_leaf)
		#--------------------------------------------------------------------'''
		self.sendHello()
		self.stateCon = 1

	
	# 0 = start, 1 = first hello sent, 2 = ongoing - data, 3 = cloes		
	def data_received(self, data):
		print("recieved Type SITH\n")
		self._deserializer.update(data)

		for SITHpacket in self._deserializer.nextPackets():
			print("Got {} from the sender.".format(SITHpacket.Type))
			
			#states: Connecring - 0, Ongoing - 1, Established - 2, FIN - 3
			if "HELLO" in SITHpacket.Type and self.stateCon == 1:
				
				self.otherSideCert = SITHpacket.Certificate
				#------check cert---------
				if not self.RootcheckCerts(self.otherSideCert):
					self.connection_lost("bad certificate")
				#-------------------------
				self.otherSideRand = SITHpacket.Random #int(randddd.decode()) to decode if needed
				self.otherSidePublicKey = X25519PublicKey.from_public_bytes(SITHpacket.PublicValue)
				self.otherSideHello = SITHpacket.__serialize__() #storing other Hello message from the other side
				self.stateCon = 2
				self.driveKeys()
				self.sendFinish()
				

			if "FINISH" in SITHpacket.Type and self.stateCon == 2:
				self.checkFinish(SITHpacket.Signature)
				self.stateCon = 3
				print("My state Is:")
				print(self.stateCon)
				self.higherProtocol().connection_made(self.SITHtransport)	

			elif "DATA" in SITHpacket.Type and self.stateCon == 3:
				print("im in decrypt data")
				de_data = self.AEAD_decrypt(SITHpacket.Ciphertext)
				#----------------------send up------------
				self.higherProtocol().data_received(de_data)
				#-----------------------------------------
			
			elif "CLOSE" in SITHpacket.Type and self.stateCon == 3:
				de_data = self.AEAD_decrypt(SITHpacket.Ciphertext).decode()
				#de_data = SITHpacket.Ciphertext.decode()
				print("close connection because ,,, {} ,,,".format(de_data))
				self.higherProtocol().connection_lost(de_data)

	def driveKeys(self):
		print("Im client")
		#----keys for AES-----------------------------------------------------
		self.sharedSecret = self.private_key.exchange(self.otherSidePublicKey)
		#self.sharedSecret = sha256(self.otherSidePublicKey.public_bytes() + bytes(0)) #self.private_key)
		self.sharedPacketSecret = sha256(self.otherSideHello + self.hello).digest()
		self.client_iv = sha256(self.sharedSecret + self.sharedPacketSecret).digest()[:12]
		self.server_iv = sha256(self.sharedSecret + self.sharedPacketSecret).digest()[12:24]
		self.write_key = sha256(sha256(self.sharedSecret + self.sharedPacketSecret).digest()).digest()[16:]
		self.read_key = sha256(sha256(self.sharedSecret + self.sharedPacketSecret).digest()).digest()[:16]
		print("shared secret: {}\n shared packet secret: {}\n write key: {}\n read key: {}\n client iv: {}\n server iv: {}".format(self.sharedSecret, self.sharedPacketSecret, self.write_key, self.read_key, self.client_iv, self.server_iv))
		
	
	def AEAD_decrypt(self, Ciphertext):
		aesgcm = AESGCM(self.read_key)
		print("the ciphertext is: {}".format(Ciphertext))
		pt = aesgcm.decrypt(self.server_iv, Ciphertext, None)
		
		return pt
	
		
	def AEAD_encrypt(self, text):
		aesgcm = AESGCM(self.write_key)
		ct = aesgcm.encrypt(self.client_iv, text, None)
		print("the ciphertext is: {}".format(ct))
		return ct


#----------end class------------
class SithServerProtocol(SITH):
	
	def connection_made(self, transport):
		print("Received a connection from SITH client")
		self.transport = transport
		self.SITHtransport = ATPtransport(self.transport, self)
		#-----generating the server certificate-----------------
		in_file = open("80085_2_signed.cert", "rb") # opening for [r]eading as [b]inary
		data_leaf = in_file.read() # if you only wanted to read 512 bytes, do .read(512)
		self.certlist.append(data_leaf)
		#--------------------------------------------------------------------
		print("Received a connection from SITH client")


	# 0 = start, 1 = first hello sent, 2 = ongoing - data, 3 = cloes		
	def data_received(self, data):
		print("recieved Type SITH\n")
		self._deserializer.update(data)

		for SITHpacket in self._deserializer.nextPackets():
			print("Got {} from the sender.".format(SITHpacket.Type))
			
			#states: Connecring - 0, Ongoing - 1, Established - 2, FIN - 3
			if "HELLO" in SITHpacket.Type and self.stateCon == 0:
				print("My state Is:")
				print(self.stateCon)
				self.otherSideCert = SITHpacket.Certificate
				#------check cert---------
				if not self.RootcheckCerts(self.otherSideCert):
					self.CRL.append(SITHpacket)######append in the list inside the method
					self.connection_lost("bad certificate")
				#-------------------------
				self.otherSideRand = SITHpacket.Random #int(randddd.decode()) to decode if needed
				self.otherSidePublicKey = X25519PublicKey.from_public_bytes(SITHpacket.PublicValue)
				self.otherSideHello = SITHpacket.__serialize__()#storing other Hello message from the other side
				#the difference
				self.sendHello()
				self.stateCon = 1
				#--------------
				self.driveKeys()

				
			if "FINISH" in SITHpacket.Type and self.stateCon == 1:
				self.checkFinish(SITHpacket.Signature)
				self.stateCon = 2
				print("My state Is:")
				print(self.stateCon)
				self.sendFinish()
				self.higherProtocol().connection_made(self.SITHtransport)
				
				
			elif "DATA" in SITHpacket.Type and self.stateCon == 2:
				print("im in decrypt data")
				de_data = self.AEAD_decrypt(SITHpacket.Ciphertext)
				#----------------------send up------------
				self.higherProtocol().data_received(de_data)
				#-----------------------------------------
		
			elif "CLOSE" in SITHpacket.Type and self.stateCon == 2:
				de_data = self.AEAD_decrypt(SITHpacket.Ciphertext).decode()
				print("close connection because ,,, {} ,,,".format(de_data))
				self.higherProtocol().connection_lost(de_data)
				
					
	def driveKeys(self):
		print("im server")
		#----keys for AES-----------------------------------------------------
		self.sharedSecret = self.private_key.exchange(self.otherSidePublicKey)
		#self.sharedSecret = sha256(self.otherSidePublicKey.public_bytes() + bytes(0)) #self.private_key)
		self.sharedPacketSecret = sha256(self.hello + self.otherSideHello).digest()
		self.server_iv = sha256(self.sharedSecret + self.sharedPacketSecret).digest()[12:24]		
		self.client_iv = sha256(self.sharedSecret + self.sharedPacketSecret).digest()[:12]
		self.write_key = sha256(sha256(self.sharedSecret + self.sharedPacketSecret).digest()).digest()[:16]
		self.read_key = sha256(sha256(self.sharedSecret + self.sharedPacketSecret).digest()).digest()[16:]
		print("shared secret: {}\n shared packet secret: {}\n write key: {}\n read key: {}\n client iv: {}\n server iv: {}".format(self.sharedSecret, self.sharedPacketSecret, self.write_key, self.read_key, self.client_iv, self.server_iv))


	def AEAD_decrypt(self, Ciphertext):
		aesgcm = AESGCM(self.read_key)
		print("the ciphertext is: {}".format(Ciphertext))
		pt = aesgcm.decrypt(self.client_iv, Ciphertext, None)
		
		return pt
	
		
	def AEAD_encrypt(self, text):
		aesgcm = AESGCM(self.write_key)
		ct = aesgcm.encrypt(self.server_iv, text, None)
		print("the ciphertext is: {}".format(ct))
		return ct
	
	
#----------end class------------
class ATPtransport(StackingTransport):
	def __init__(self, transport, protocol):
		super().__init__(transport)
		self.protocol = protocol
		self.transport = transport
		
	def write(self, data):
		en_data = self.protocol.AEAD_encrypt(data)
		self.protocol.sendDataDown(en_data)
		#self.transport.write(data)
	
	def close(self):
		self.protocol.connection_lost("Fin is established")


#----------end class------------
#lab1ClientFactory = StackingProtocolFactory(lambda: RIPclient())
#lab1ServerFactory = StackingProtocolFactory(lambda: RIPserver())
