import socket
import sys

# Create socket (allows two computers to talk)

def create_socket():
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
		socket.bind((host, port))

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
 

  
  

