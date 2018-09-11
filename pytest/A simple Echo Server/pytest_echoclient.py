import asyncio
import socket
import sys
import time
import os.path

message = sys.argv[2]
port = sys.argv[1]
Addre = socket.gethostname()
timenow = str(time.time())
async def tcp_echo_client(message, loop):
    reader, writer = await asyncio.open_connection(Addre, port,
                                                   loop=loop)
    print('Send: %r' % message)
    writer.write(message.encode())

    data = await reader.read(100)
    RecMessage = data.decode()
    print('Received: %r' % RecMessage)

    counter = 1
    while (True):
        if (os.path.isfile("./echo_response_"+str(counter)+".txt")):
           counter = counter + 1
        else:
            textfile = open(f"echo_response_"+str(counter)+".txt", "w")
            textfile.write(f"{timenow}\n")
            textfile.write(RecMessage)
            textfile.close()
            break

    print('Close the socket')
    writer.close()


loop = asyncio.get_event_loop()
loop.run_until_complete(tcp_echo_client(message, loop))
loop.close()
