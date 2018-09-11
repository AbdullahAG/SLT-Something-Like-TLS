import asyncio
import socket
import sys
import time

port = sys.argv[1]
Addre = socket.gethostname()
async def eightball_client(loop):
    reader, writer = await asyncio.open_connection(Addre, port,
                                                   loop=loop)
    
    index = 0
    timenow = str(time.time())
    plaintext = input("please write your question/ nothing to exit: \n")
    while (plaintext):
        writer.write(plaintext.encode())
        respone = await reader.read(100)
        answer = respone.decode()
        print (answer)

        indextxt = index+1
        textfile = open(f"8ball_response_{indextxt}.txt", "w")
        textfile.write(f"Timestamp : {timenow}\n")
        textfile.write(f"Question : {plaintext}\n")
        textfile.write(f"Answer : {answer}")
        textfile.close()

        plaintext = input("please write your question/ nothing to exit: \n")
        index = index+1

    print('Close the socket')
    writer.close()


loop = asyncio.get_event_loop()
loop.run_until_complete(eightball_client(loop))
loop.close()
