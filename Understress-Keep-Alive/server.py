from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import threading
import time

MAX_CONNECTIONS = 10
active_connections = 0
lock = threading.Lock()

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global active_connections
        with lock:
            active_connections += 1
            current_count = active_connections
            print(f"Active connections: {current_count}")
            
            if current_count > MAX_CONNECTIONS:
                self.send_error(503, "Server overloaded")
                active_connections -= 1
                return
        
        try:
            # Simulate some processing time to keep connections active
            time.sleep(2)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Hello\n")
        finally:
            with lock:
                active_connections -= 1

    def log_message(self, format, *args):
        return

if __name__ == "__main__":
    server = ThreadingHTTPServer(("localhost", 3000), SimpleHandler)  # Key change here
    print("Server running on port 3000")
    server.serve_forever()
