# SLT: Something Like TLS
This project depends on The Playground uper and lower Protocols. My project is the "middleware" protocols where it needs to connect to the upper and lower protocols. The SLT protocl will be assume the rule of TLS, but in reality the whole project is within the actual application layer where The playground protocls will simulate an actual network stack.  

I'm using Python’s asyncio library instead of (direct) socket access. Sockets are a form of “synchronous” communication. That means that the code moves in the typical flow from beginning to end.

