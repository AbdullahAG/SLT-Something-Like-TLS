from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from playground.common import Timer, Seconds
from playground.network.packet import PacketType, FIELD_NOT_SET
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.packet.fieldtypes import UINT8, UINT32, BUFFER, STRING
import asyncio
import hashlib
import random
import sys

#packet creation
class RIPPacket(PacketType):
	DEFINITION_IDENTIFIER = "RIP.abdullah.packet"
	DEFINITION_VERSION = "1.0"
	
	FIELDS = [
	
	("Type", STRING),
	("SeqNo", UINT32),
	("AckNo", UINT32),
	("CRC", BUFFER),
	("Data", BUFFER),

	]
#----------end class------------
class RIP(StackingProtocol):
	def __init__(self):
		super().__init__()
		self.transport = None
		self.timeoutValue = 10#the RIP layer will wait for 10 seconds until resending the packet
		self.SequenceNo = random.randrange(0, 101, 2)
		self.stateCon = 0#open server
		self.sentBoxData = []# tupple(Sequence Number, Packet object, Timer, Acked or Not)
		self.recieveBoxData = []# tupple(Sequence Number, Packet object, Acked or Not)
		self.sentHand = None#sent message from handshake
		self.recHand = None#recieved message from hanshake
		self.timHand = None#timer for hanshake
		self.firstCon = True#first packet flag
		self._deserializer = RIPPacket.Deserializer()
		
		
	# 1 = SYN, 2 = ACK, 3 = FIN 4 = DATA
	def connection_made(self, transport):
		print("Received a connection from {}".format(transport.get_extra_info("peername")))
		self.transport = transport
		self.PassTransport =  ATPtransport(self.transport, self)
		print("im here in connection made")
		loop = asyncio.new_event_loop()
		asyncio.set_event_loop(loop)
		
		
	def connection_lost(self, exc):
		# self.send("FIN", b"")
		# self.send("FIN", b"")
		# self.send("FIN", b"")#third time is the charm
		self.higherProtocol().connection_lost(exc)
		#loop = asyncio.get_event_loop()
		#loop.stop()
	
				
	def data_received(self, data):
		print("data_recieved start")
		self._deserializer.update(data)
		
		for atppacket in self._deserializer.nextPackets():
			print(atppacket.Data)
			print("Got {} from the sender.".format(atppacket.Type))
			
			#check for doublicate and hash
			if self.recieveBoxData or self.recHand:
				if not self.checkPacket(atppacket):
					print("error packet")
					return
			
			#add to list
			print("recieved Type ={}, Seq= {}, ACK= {} ".format(atppacket.Type, atppacket.SeqNo, atppacket.AckNo))
			print("And the Connection is {}".format(self.stateCon))
			#end check
			
			#states: Connecring - 0, Ongoing - 1, Established - 2, FIN - 3
			if "SYN" in atppacket.Type and self.stateCon == 0:#SYN SENT and Connection is open((server))
				self.handleHandshake(1, atppacket)

		
			elif "SYN" in atppacket.Type and "ACK" in atppacket.Type and self.stateCon == 1:#SYN ACK and Connection is ongoing((client))
				print("the timer object is: {}".format(self.timHand))
				timerHandshake = self.timHand
				self.timHand.cancel()
				self.timHand = timerHandshake
				print("Timer is canceled")
				self.handleHandshake(2, atppacket)
				
			
			
			elif "ACK" in atppacket.Type:
				if self.stateCon == 3:
					if self.sentBoxData[-1][0]+len(self.sentBoxData[-1][1].Data) == atppacket.AckNo:
						finTimer = self.sentBoxData[-1][2]
						finTimer.cancel()
						self.transport.close()
							
				if self.stateCon == 1:#SYN ACK ACK and Connection is established((server))
					print("the timer object is: {}".format(self.timHand))
					timerHandshake = self.timHand
					self.timHand.cancel()
					self.timHand = timerHandshake					
					print("Timer is canceled")
					self.handleHandshake(3, atppacket)

				elif self.stateCon == 2:
					self.recieveAck(atppacket)
					print("ACKnowledged")
			
			
			#the end of the handshake
			elif "DATA" in atppacket.Type.upper() and self.stateCon == 2:#DATA and connection is established((serverANDclient))
				print("Got a packet {}".format(atppacket))
				self.recieveData(atppacket)
				
			
			elif "FIN" in atppacket.Type.upper() and self.stateCon == 2:#FIN((server))
				print("Got a FIN packet {}".format(atppacket))
				self.stateCon = 3
				self.connection_lost("FIN")
				
				self.sendAck(atppacket)
				for n in range(len(self.recieveBoxData)):
					if self.recieveBoxData[n][2] is False and "DATA" in self.recieveBoxData[n][1].Type.upper():#Acked is True
						return
					
				self.transport.close()#close when you get an Ack for the fin
			
			else:
				print("the packet has a wrong type")
				if self.stateCon == 0:
					self.transport.close()
	
	def handleHandshake(self, Type, handPacket):
		if Type == 1 and self.recHand is None:#SYN
			self.recHand = handPacket
			self.send("SYN ACK", b"")#SYN ACK
			self.stateCon = 1#Ongoing
			#self.timHand.cancel()
			print("The connection is {}".format(self.stateCon))
			print("SYN and an ACK is sent,and the Ack number is  {}".format(handPacket.SeqNo + 1))
			
		elif Type == 2 and self.recHand is None:#SYN ACK
			if handPacket.AckNo - 1 == self.sentHand.SeqNo:
				self.recHand = handPacket
				self.send("ACK", b"")#SYN ACK ACK
				print("SYN:REC and an ACK is sent. The packet state is Established. The Ack number is{}".format(handPacket.SeqNo + 1))
				self.higherProtocol().connection_made(self.PassTransport)
				self.stateCon = 2#established with server
				#self.timHand.cancel()
				print("\nconnection is made with server")
				self.SequenceNo =  self.SequenceNo - 1#for the first Data packet
			else:
				print("wrong SYN ACK")
				
		elif Type == 3 and "SYN" in self.recHand.Type:#SYN ACK ACK
			if handPacket.AckNo - 1 == self.sentHand.SeqNo:
					self.recHand = handPacket
					print("Got SYN ACK ACK, and the sequence number is  {}".format(handPacket.SeqNo))
					print("\nconnection is made with client")
					#self.timHand.cancel()
					self.higherProtocol().connection_made(self.PassTransport)#server connection
					self.stateCon = 2#established
			else:
				print("wrong SYN ACK ACK")				
	
	
	def recieveData(self, dataPacket):
		#add to the list
		self.recieveBoxData.append((dataPacket.SeqNo, dataPacket, False))#Acked is false
		#sort
		self.recieveBoxData.sort()
		#print the list
		completeFlag = True
		for seq, packet, acked in self.recieveBoxData:
			print("Seq= {}, Packet= {}, Acked= {}".format(seq, packet, acked))
			if acked is False and packet.Type.upper() == "DATA":
				completeFlag = False

		if dataPacket.Type == "FIN" and completeFlag:
			self.sendAck(dataPacket)
			self.transport.close()
			
		print("Number of Packets are: {}".format(len(self.recieveBoxData)))		
		#send to higher protocol and remove packets
		lastPacket = None
		appData = b""
		index = 1
		if len(self.recieveBoxData) != 1:
			for index in range(len(self.recieveBoxData)):
				pefIndex = index - 1
				if self.recieveBoxData[index][2] is False and self.recieveBoxData[index][0] == self.recieveBoxData[pefIndex][0] + len(self.recieveBoxData[pefIndex][1].Data):
					#send current packet data to application	
					lastPacket = self.recieveBoxData[index][1]
					self.recieveBoxData[index] = (self.recieveBoxData[index][0], self.recieveBoxData[index][1], True)#because tuples dont support update, so reassigment to the index with Acked True
					print(" A: This acked packet seq no is {}".format(self.recieveBoxData[index][0]))
					appData = appData + self.recieveBoxData[index][1].Data#add data
					index = index + 1
		else:
			self.recieveBoxData[0] = (self.recieveBoxData[0][0], self.recieveBoxData[0][1], True)
			lastPacket = self.recieveBoxData[0][1]
			appData = lastPacket.Data
		#acked all data packets
		self.sendAck(lastPacket)
		#print
		for seq, packet, acked in self.recieveBoxData:
			print("Seq= {}, Packet= {}, Acked= {}".format(seq, packet, acked))
		#send data to the application layer
		self.higherProtocol().data_received(appData)		
		
		
	def recieveAck(self, ackPacket):
		#packetIndex = 0
		for Seq, dataPacket, timer, acked in self.sentBoxData:
			print("ACKnowledgment for Seq= {}, Data packet ACK= {}, Timer= {}, Acked= {} and recieved ACK is= {}".format(Seq, Seq+len(dataPacket.Data), timer, acked, ackPacket.AckNo))
			if Seq + len(dataPacket.Data) == ackPacket.AckNo and acked is False:#if the ack matches the list value
				packetIndex = self.sentBoxData.index((Seq, dataPacket, timer, acked)) + 1#index starts with 0, while range starts with 1
				print("loooooop for {}".format(packetIndex))
				for n in range(packetIndex):#find the timer in the dictionary using the seq number
					print("In loop for Seq= {}, Data packet ACK= {}, Acked= {} and recieved ACK is= {}".format(self.sentBoxData[n][0], self.sentBoxData[n][0]+len(self.sentBoxData[n][1].Data), self.sentBoxData[n][3], ackPacket.AckNo))
					#cancel all the timer less than the seq number
					currentTimer = self.sentBoxData[n][2]#timer cancelation
					currentTimer.cancel()
					print("timer is canceled")
					self.sentBoxData[n] = (self.sentBoxData[n][0], self.sentBoxData[n][1], currentTimer, True)
					#self.timerDict[packetSeq] = timer.cancel()
				return	
			else:
				print("No match this packet= {} : Acked packet= {}".format(len(dataPacket.Data) + Seq, ackPacket.AckNo))				

				
	def checkPacket(self, packet):
		#loop dic if exist send from to last acked packet and check doublications
		if "DATA" in packet.Type.upper():
			for packetSeq, DataPacket, acked in self.recieveBoxData:
				if packetSeq == packet.SeqNo:
					if acked is True:
						self.sendAck(DataPacket)#acked data packet, resend ACK
						return False
					elif acked is False:#for doubliction Data packets
						return False

		#check Hash
		checkedHash = self.hashPacket(packet)
		print("Checked Checksum is: "+checkedHash.decode())
		if packet.CRC != checkedHash:
			print("the packet has been modefied")
			return False
		return True			
			
			
	def hashPacket(self, hashPacket):
		print("start hashing")
		ATPpacket = RIPPacket(Type = hashPacket.Type,  SeqNo = hashPacket.SeqNo, AckNo = hashPacket.AckNo, CRC = b"", Data = hashPacket.Data)
		checksum = hashlib.sha256(ATPpacket.__serialize__()).hexdigest()
		checksum = checksum.encode()
		return checksum	
		
		
	def sendAck(self, packetAck):
		sentAck = RIPPacket()
		#add Ack number
		sentAck.AckNo = packetAck.SeqNo + len(packetAck.Data)#sequence number and data length of previouse recieved packet
		#add Seq
		sentAck.SeqNo = 0
		#add Type
		sentAck.Type = "ACK"
		#add Data
		sentAck.Data = b""
		#add checksum
		sentAck.CRC = self.hashPacket(sentAck)
		print("checksum is: {}".format(sentAck.CRC.decode()))
		print("send Type ={}, Seq= {}, ACK= {}".format(sentAck.Type, sentAck.SeqNo, sentAck.AckNo))
		#add packet to the sent list
		self.transport.write(sentAck.__serialize__())
		print("the ACK is sent for: {}".format(sentAck.AckNo))
		
		
	def send(self, pacType, PacData):	
		sentPacket = RIPPacket()
		print("the packet type is: {}".format(pacType))
		#calculateSeqAck
		if "SYN" in pacType.upper() and "ACK" in pacType.upper():
			print("SYN ACK")
			#add Ack number
			sentPacket.AckNo = self.recHand.SeqNo + 1
			#add Seq
			sentPacket.SeqNo = self.SequenceNo#random seq
			
		elif "ACK" in pacType.upper():
			if self.stateCon == 1:
				print("1 ACK")	
				#add Ack number
				sentPacket.AckNo = self.recHand.SeqNo + 1
				#add Seq
				sentPacket.SeqNo = self.sentHand.SeqNo + 1
						
		elif "SYN" in pacType.upper():
			print("SYN")
			#add Ack number
			sentPacket.AckNo = 0
			#add Seq
			sentPacket.SeqNo = self.SequenceNo#random seq
			
		elif "DATA" in pacType.upper() or "FIN" in pacType.upper():
			if self.sentHand is not None:
				print("1st Packet after the Handshake")
				#add Ack number
				sentPacket.AckNo = 0
				#add Seq
				sentPacket.SeqNo = self.recHand.AckNo
				#empty hands
				self.recHand = None
				self.sentHand = None
			else:	
				#add Ack number
				sentPacket.AckNo = 0
				#add Seq
				sentPacket.SeqNo = self.sentBoxData[-1][0]+ len(self.sentBoxData[-1][1].Data)#sequence number and data length of previouse sent packet

			if "FIN" in pacType.upper() :
				self.stateCon = 3#FIN state
		else:
			print("IM NOTHING{}".format(sentPacket.AckNo))
			
		#add Type
		sentPacket.Type = pacType
		
		#add Data
		sentPacket.Data = PacData
		
		#add checksum
		sentPacket.CRC = self.hashPacket(sentPacket)
		print("checksum is: {}".format(sentPacket.CRC.decode()))
		print("send Type ={}, Seq= {}, ACK= {}".format(sentPacket.Type, sentPacket.SeqNo, sentPacket.AckNo))
		#add packet to the sent list
		
		if "DATA" in pacType.upper() or "FIN" in pacType.upper():#not SYN ACK since it will go to the first option
			pacTimer = Timer(Seconds(self.timeoutValue), self.timeout, sentPacket)
			pacTimer.start()
			self.sentBoxData.append((sentPacket.SeqNo, sentPacket, pacTimer, False))#packet seq, packet, timer, acked or not
			print("the packe is sent and next Seq number is:{}".format(sentPacket.SeqNo+len(sentPacket.Data)))
			
		elif "SYN" in pacType.upper() or "SYN" in pacType.upper() and "ACK" in pacType.upper():
			print("starting a SYN or SYN ACK handshake packets timer")
			self.sentHand = sentPacket
			self.timHand = Timer(Seconds(self.timeoutValue), self.timeout, self.sentHand)
			self.timHand.start()
			print("the timer object is: {}".format(self.timHand))
			print("the packe is sent and next Seq number is:{}".format(sentPacket.SeqNo+1))

		#write packet
		serPacket = sentPacket.__serialize__()
		self.transport.write(sentPacket.__serialize__())
	
	
		
	def resend(self, resntPacket):		
		if "DATA" in resntPacket.Type.upper():#start timer again
			#get timer
			for seq, packet, timer, acked in self.sentBoxData:
				if seq == resntPacket.SeqNo:
					timer.cancel()
					pacTimer = Timer(Seconds(self.timeoutValue), self.timeout, packet)
					pacTimer.start()
					index = self.sentBoxData.index((seq, packet, timer, acked))
					self.sentBoxData[index] = (seq, packet, pacTimer, False)#packet seq, packet, timer, acked or not
					#start timer
		elif "FIN" in resntPacket.Type.upper():
			currentTimer = self.sentBoxData[-1][2]
			currentTimer.cancel()
			currentTimer = Timer(Seconds(self.timeoutValue), self.timeout, self.sentBoxData[-1][1])
			currentTimer.start()
			self.sentBoxData[-1] = (self.sentBoxData[-1][0], self.sentBoxData[-1][1], currentTimer, False)#last packet since its FIN
		elif "ACK" in resntPacket.Type.upper():
			if "SYN" in resntPacket.Type.upper():
				self.timHand.cancel()
			self.timHand = Timer(Seconds(self.timeoutValue), self.timeout, self.sentHand)
			self.timHand.start()
			
		resendPacket = RIPPacket(Type = resntPacket.Type, SeqNo = resntPacket.SeqNo, AckNo = resntPacket.AckNo, CRC = resntPacket.CRC, Data = resntPacket.Data)
		self.transport.write(resendPacket.__serialize__())

	
		
	def timeout(self, timedPacket):
		print("\ntimeout\nresend packet {}".format(timedPacket.SeqNo))
		self.resend(timedPacket)

	
#----------end class------------
class RIPclient(RIP):

	def connection_made(self, transport):
		print("Received a connection from {}".format(transport.get_extra_info("peername")))
		self.transport = transport
		self.PassTransport =  ATPtransport(self.transport, self)
		
		if self.firstCon:
			print("im first packet")
			self.firstpacket()
		self.stateCon = 1	
		print("im here in connection made")	
		
	
	def firstpacket(self):
		#the start of the handshake
		print("HandShake start")
		self.send("SYN ", b"")#SYN sent
		print("First Hand")
		self.firstCon = False
				

#----------end class------------
class RIPserver(RIP):
	pass

#----------end class------------
class ATPtransport(StackingTransport):
	def __init__(self, transport, protocol):
		super().__init__(transport)
		self.protocol = protocol
		self.transport = transport
		
	def write(self, data):	
		self.writeInChuncks(data)
		#self.transport.write(data)
		
		
	def writeInChuncks(self, data):
		dataLimit = 1500
		
		if len(data) > dataLimit:
			print("----------------------------Starting with {} bytes of data".format(len(data)))
			while len(data) > 0:
				# let’s take of a 10 byte chunk
				chunk, data = data[:dataLimit], data[dataLimit:]
				self.protocol.send("DATA", chunk)
				print("----------------------------Another 10 bytes loaded into deserializer. Left={}".format(len(data)))
		else:
			print("---------------------------------less than 1500")
			self.protocol.send("DATA", data)
	
	
	def close(self):
		self.protocol.send("FIN", b"")
		self.protocol.connection_lost("Fin is established")


#----------end class------------
lab1ClientFactory = StackingProtocolFactory(lambda: RIPclient())
lab1ServerFactory = StackingProtocolFactory(lambda: RIPserver())
