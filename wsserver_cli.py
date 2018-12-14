import sys
import socket
import asyncore
import wsserver

wshandlers = []

class WebSocketHandler(wsserver.dispatcher):
	def __init__(self, sock=None):
		wsserver.dispatcher.__init__(self, sock=sock)
	def onmessage(self, data):
		for h in wshandlers:
			h.snd(data)
	def onclose(self):
		print 'onclose'

class WebSocketServer(wsserver.dispatcher):
	def __init__(self, addr):
		wsserver.dispatcher.__init__(self)
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.set_reuse_addr()
		self.bind(addr)
		self.listen(5)
	def onconnect(self):
		sock, addr = self.accept()
		print 'new connection from %s' % repr(addr)
		wshandlers.append(WebSocketHandler(sock=sock))

		
if len(sys.argv) != 2:
	print "Benutzung: python %s <port>"%sys.argv[0]
	sys.exit(1)
try:
	port = int(sys.argv[1]);
except:
	print "%s ist keine Portnummer"%sys.argv[1]
	sys.exit(1)

if port < 1 or port > 65535:
	print "Die Pornummer muss zwischen 1 und 65535 liegen"
	sys.exit(1)

WebSocketServer(('127.0.0.1',port))
asyncore.loop(use_poll=True)