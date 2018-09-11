import asyncio
import socket
import sys
import time
import os.path
import cryptography.fernet as fer #pip install cryptography


port = sys.argv[1]
key = fer.Fernet.generate_key()
timenow = str(time.time())
password = fer.Fernet(key)
async def secure_message_server(reader, writer):
    print("Waiting for Client to connect...")
    addr = writer.get_extra_info('peername')[0]
    print("Client port %r address %r" % (port, addr))

    plaintxt = await reader.read(100)
    Plain = plaintxt.decode()

    if (Plain == "__EXIT__"):
        server.close()
        loop.stop()
        loop.close()
        
    encrpttxt = password.encrypt(plaintxt)
    print("cipher, %r" % encrpttxt.decode())
    writer.write(encrpttxt)

    await asyncio.sleep(1)

    ciphertxt = await reader.read(100) # for decrypt, C
    Cipher = ciphertxt.decode()
    decrypttx = password.decrypt(encrpttxt)
    print("plain, %r" % decrypttx.decode())
    writer.write(decrypttx)

    counter = 1
    while (True):
        if (os.path.isfile("./security_message_"+str(counter)+".txt")):
            counter = counter + 1
        else:
            textfile = open(f"security_message_"+str(counter)+".txt", "w")
            textfile.write(f"Timestamp : {timenow}\n")
            textfile.write(f"plaintext : {Plain}\n")
            textfile.write(f"ciphertext : {Cipher}")
            textfile.close()
            break


    print("Close the client socket")
    writer.close()

loop = asyncio.get_event_loop()
coro = asyncio.start_server(secure_message_server, socket.gethostname(), port, loop=loop)
server = loop.run_until_complete(coro)

try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

    
