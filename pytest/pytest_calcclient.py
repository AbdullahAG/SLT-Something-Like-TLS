import asyncio
import socket
import sys
import time
import os.path

port = sys.argv[1]
plaintext = sys.argv[2]
Addre = socket.gethostname()
async def secure_message_client(loop):
    reader, writer = await asyncio.open_connection(Addre, port,
                                                   loop=loop)
    
    timenow = str(time.time())
    print('The Problem: %r' % plaintext)
    writer.write(plaintext.encode())

    plainresult = await reader.read(100) #result of the math problem
    result = plainresult.decode()
    result = eval(result)
    print('Result: %r' % result)

    counter = 1
    while (True):
        if (os.path.isfile("./calc_response_"+str(counter)+".txt")):
           counter = counter + 1
        else:
           textfile = open(f"calc_response_"+str(counter)+".txt", "w")
           textfile.write(f"{timenow}\n")
           textfile.write(f"Math Problem : {plaintext}\n")
           textfile.write(f"Result : {result}")
           textfile.close()
           break
           

    print('Close the socket')
    writer.close()


loop = asyncio.get_event_loop()
loop.run_until_complete(secure_message_client(loop))
loop.close()
