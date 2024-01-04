import socket
import sys

# Create socket (allows two computers to talk)

def socket_create():
	try: 
		global host
		global port
		global s
		host = ''
		port = 9999 # don't choose a common one
		s = socket.socket()
	except socket.error as msg:
		print('Socket Creation Error: ' + str(msg))

# Bind socket to port and wait for connection from client

def socket_bind():
	try: 
		global host
		global port
		global s

		# print to track binding attempts
		print('Binding socket to port: ' + str(port))
		s.bind((host, port))

		# VERY IMPORTANT, 5 is # of bad connections before refusing
		s.listen(5)
	except socket.error as msg:
		print('Socket Binding Error: ' + str(msg) + '\n' + "Retrying...")
		socket_bind()

# Establish a connection with client

def socket_accept():

    # s.accept returns an array: [IP, Port,...]
	conn, address = s.accept()
	print('Connection has been established | IP: ' + address[0] + ' | Port: ' + str(address[1]))

	# not created yet
	send_commands(conn) 
	conn.close()

# send commands to client
def send_commands(conn):
	while True:
		cmd = input()
		if cmd == 'quit':
			conn.close()
			s.close()
			sys.exit()
		if len(str.encode(cmd)) > 0:
			conn.send(str.encode(cmd))
			client_response = str(conn.recv(1024), 'utf-8')
			print(client_response, end = '')

def main():
	socket_create()
	socket_bind()
	socket_accept()

main()

 

  
  

