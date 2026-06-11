import socket


#./passt -f -s /tmp/passt.socket -t 12345

HOST = "192.168.1.18"
PORT = 12345

msg="Demande de confirmation de reception"
print("envoie de la demande au serveur")

try:
	with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
		s.settimeout(15)
		s.connect((HOST,PORT))
		s.sendall(msg.encode())
		data=s.recv(2048)
		
		print("Message envoyé")
		
		if data.startswith(b"TA_SIGNED_CONFIRMATION:"):
			sig=data.split(b":")[1]
			print(f"Reçu confirmation : {sig}")
		else:
			print("erreur : {data.decode()}")
			s.close()
except socket.timeout:
	print("Délai dépassé")
	s.close()
except Exception as e:
	print("erreur de connexion ou de transmission")
	s.close()
