import asyncio
import socket
import sys
import time
import os.path

port = sys.argv[1]
plaintext = sys.argv[2]
Addre = socket.gethostname()
timenow = str(time.time())
async def eightball_client(loop):
    reader, writer = await asyncio.open_connection(Addre, port,
                                                   loop=loop)
    writer.write(plaintext.encode())
    respone = await reader.read(100)
    answer = respone.decode()
    print (answer)

    counter = 1
    while (True):
        if (os.path.isfile("./8ball_response_"+str(counter)+".txt")):
            counter = counter + 1
        else:
            textfile = open(f"8ball_response_"+str(counter)+".txt", "w")
            textfile.write(f"Timestamp : {timenow}\n")
            textfile.write(f"Question : {plaintext}\n")
            textfile.write(f"Answer : {answer}")
            textfile.close()
            break

    print('Close the socket')
    writer.close()


loop = asyncio.get_event_loop()
loop.run_until_complete(eightball_client(loop))
loop.close()
