import asyncio
import socket
import sys
import time
import os.path

port = sys.argv[1]
plaintext = sys.argv[2]
timenow = str(time.time())
Addre = socket.gethostname()
async def secure_message_client(loop):
    reader, writer = await asyncio.open_connection(Addre, port,
                                                   loop=loop)    

    print('encrypt: %r' % plaintext)
    writer.write(plaintext.encode())
    
    await asyncio.sleep(1)
    
    txt = await reader.read(100) #encrypted text
    encrypttext = txt.decode()
    print('Cipher: %r' % encrypttext)
    writer.write(encrypttext.encode())
    
    await asyncio.sleep(1)
    
    txt = await reader.read(100) #plaintext text
    plaintxt = txt.decode()
    print('Dicipher: %r' % plaintxt)

    counter = 1
    while (True):
        if (os.path.isfile("./security_response_"+str(counter)+".txt")):
            counter = counter + 1
        else:
            textfile = open(f"security_response_"+str(counter)+".txt", "w")
            textfile.write(f"{timenow}\n")
            textfile.write(f"ciphertext : {encrypttext}\n")
            textfile.write(f"plaintext : {plaintxt}")
            textfile.close()
            break

    print('Close the socket')
    writer.close()


loop = asyncio.get_event_loop()
loop.run_until_complete(secure_message_client(loop))
loop.close()
