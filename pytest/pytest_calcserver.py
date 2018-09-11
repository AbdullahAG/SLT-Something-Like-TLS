import asyncio
import socket
import sys
import time
import os.path


port = sys.argv[1]
async def secure_message_server(reader, writer):
    print("Waiting for Client to connect...")
    addr = writer.get_extra_info('peername')[0]
    print("Client port %r address %r" % (port, addr))
    timenow = str(time.time())
    
    plaintext = await reader.read(100)
    mathProb = plaintext.decode()

    if (mathProb == "__EXIT__"):
        server.close()
        loop.stop()
        loop.close()

    print("Math problem, %r" % mathProb)
    mathProb = mathProb.split()
    print(mathProb)

    problemLength = len(mathProb)
    x = int(problemLength/2) #to measure the iteration numbers
    mathProbCorrect = ""
    for num in range(x):
        mathProbCorrect = mathProbCorrect+"("+mathProb[(2*num)+1]+mathProb[(2*num)]
        print (mathProbCorrect)
    mathProbCorrect = mathProbCorrect+mathProb[problemLength-1]+")"*x
    print (mathProbCorrect)

    result = eval(mathProbCorrect)
    print("math Prob Correct : %r" % mathProbCorrect)
    print("result : %r" % result)
    writer.write(mathProbCorrect.encode())

    counter = 1
    while (True):
        if (os.path.isfile("./calc_message_"+str(counter)+".txt")):
           counter = counter + 1
        else:
            textfile = open(f"calc_message_"+str(counter)+".txt", "w")
            textfile.write(f"Timestamp : {timenow}\n")
            textfile.write(f"Math Problem : {mathProbCorrect}\n")
            textfile.write(f"Result : {result}")
            textfile.close()
            break

    
    print("Close the client socket")
    writer.close()

loop = asyncio.get_event_loop()
coro = asyncio.start_server(secure_message_server, socket.gethostname(), port, loop=loop)
server = loop.run_until_complete(coro)

try:
    loop.run_forever()
except:
    pass

    
