import asyncio
import socket
import sys
import time
import os.path

port = sys.argv[1]
async def handle_echo(reader, writer):
    print("Waiting for Client to connect...")
    data = await reader.read(1000)
    message = data.decode()
    
    if (message == "__EXIT__"):
        server.close()
        loop.stop()
        loop.close()

    
    addr = writer.get_extra_info('peername')[0]
    timenow = str(time.time())

    counter = 1
    while (True):
        if (os.path.isfile("./echo_message_"+str(counter)+".txt")):
            counter = counter + 1
        else:
            textfile = open(f"echo_message_"+str(counter)+".txt", "w")
            textfile.write(f"{timenow}\n")
            textfile.write(f"{addr} : {port}\n")
            textfile.write(message)
            textfile.close()
            break
        
        print("Received %r from %r" % (message, addr))
        print("Client port %r address %r" % (port, addr))
        print("Send: %r" % message)
        
        writer.write(message.encode())
        await writer.drain()

        
    print("Close the client socket")
    writer.close()

loop = asyncio.get_event_loop()
coro = asyncio.start_server(handle_echo, socket.gethostname(), port, loop=loop)
server = loop.run_until_complete(coro)

try:
    loop.run_forever()
except KeyboardInterrupt:
    pass
