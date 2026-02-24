from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

class VerifierHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        data = urllib.parse.parse_qs(post_data)
        
        print("\n" + "="*50)
        print("/!\\ LE BARMAN A RECU UNE PREUVE DU WALLET ! /!\\")
        print(f"-> Attribut 'Majeur' certifie par le TEE : {data.get('token', [''])[0]}")
        print("-> Acces autorise.")
        print("="*50 + "\n")

        self.send_response(200)
        self.end_headers()

server = HTTPServer(('0.0.0.0', 8080), VerifierHandler)
print("Le serveur du Barman ecoute sur le port 8080...")
server.serve_forever()
