import asyncio
import socket
import sys
import time
import os.path
from random import randint


port = sys.argv[1]
Respones = [None] * 8
RList = ["Your guss is as good as mine","You need a vacation",
             "Its's trump's fault","I don't Know. What do you think?",
             "Nobody ever said it would be easy, they only said it would be worth it",
             "You really expect me to answer that?","Your're going to get what you deserve.",
             "That depends on how much you're willing to pay."]
timenow = str(time.time())
Questions = []
    
# to assign the responses randomaly to a list
for num in range(8):
    while (True):
        x = randint(0,7)
        if(Respones[x] == None):
            break
    Respones[x] = RList[num]
    
async def eightball_server(reader, writer):
    print("Waiting for Client to connect...")

    plaintxt = await reader.read(100)
    question = plaintxt.decode()
    
    if (question == "__EXIT__"):
        server.close()
        loop.stop()
        loop.close()
        
    print (question)
    Questions.append(question)

        #to check if the question is already asked
    if question in Questions:
        Rindex = Questions.index(question)
        print (Respones[Rindex%8])
        respond = Respones[Rindex%8]
    else:
        Questions.append(question)
        index = index+1
        print (Respones[index%8])
        respond = Respones[index%8]

    writer.write(respond.encode())

    counter = 1
    while (True):
        if (os.path.isfile("./8ball_message_"+str(counter)+".txt")):
            counter = counter + 1
        else:
            textfile = open(f"8ball_message_"+str(counter)+".txt", "w")
            textfile.write(f"Timestamp : {timenow}\n")
            textfile.write(f"Question : {question}\n")
            textfile.write(f"Respone : {respond}\n")
            textfile.close()
            break

    
        
    print("Close the client socket")
    writer.close()

loop = asyncio.get_event_loop()
coro = asyncio.start_server(eightball_server, socket.gethostname(), port, loop=loop)
server = loop.run_until_complete(coro)

try:
    loop.run_forever()
except KeyboardInterrupt:
    pass
    
