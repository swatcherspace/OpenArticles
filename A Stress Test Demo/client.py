import requests
import threading

def send_keepalive_request():
    with requests.Session() as session:
        session.keep_alive = True  # requests.Session does this by default
        try:
            for _ in range(10):
                r = session.get("http://localhost:3000", headers={"Connection": "keep-alive"})
                print(r.status_code, r.text.strip())
        except Exception as e:
            print("Request failed:", e)

# Start many threads to simulate stress
threads = []
for _ in range(20):
    t = threading.Thread(target=send_keepalive_request)
    t.start()
    threads.append(t)

for t in threads:
    t.join()
