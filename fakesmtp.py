import socket, sys, threading

mode = sys.argv[1] if len(sys.argv) > 1 else "risky"

if mode == "risky":
    EHLO = (b"250-testmail.local Hello\r\n250-SIZE 33554432\r\n"
            b"250-VRFY\r\n250-EXPN\r\n250-8BITMIME\r\n250 HELP\r\n")
else:  # secure
    EHLO = (b"250-testmail.local Hello\r\n250-SIZE 33554432\r\n"
            b"250-STARTTLS\r\n250-8BITMIME\r\n250 HELP\r\n")

HELP = b"214 Supported commands: HELO EHLO MAIL RCPT DATA QUIT HELP\r\n"

def handle(conn):
    conn.sendall(b"220 testmail.local ESMTP\r\n")
    buf = b""
    while True:
        data = conn.recv(1024)
        if not data:
            break
        buf += data
        while b"\r\n" in buf:
            line, buf = buf.split(b"\r\n", 1)
            cmd = line.upper().split(b" ")[0]
            if cmd in (b"EHLO", b"HELO"):
                conn.sendall(EHLO)
            elif cmd == b"HELP":
                conn.sendall(HELP)
            elif cmd == b"QUIT":
                conn.sendall(b"221 Bye\r\n")
                conn.close()
                return
            else:
                conn.sendall(b"250 OK\r\n")
    conn.close()

s = socket.socket()

s.bind(("127.0.0.1", 25))
s.listen(5)
print("Fake SMTP server (" + mode + " mode) on 127.0.0.1:25. Ctrl+C to stop.")
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()