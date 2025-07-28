import socket
import struct

SERVERDATA_AUTH = 3
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_RESPONSE_VALUE = 0


class RCONClient:
    def __init__(self, host, port, password):
        self.host = host
        self.port = port
        self.password = password
        self.req_id = 0
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect((self.host, self.port))
        self._auth()

    def _auth(self):
        self.req_id += 1
        self._send_packet(self.req_id, SERVERDATA_AUTH, self.password)

        for _ in range(2):
            resp_id, resp_type, _ = self._recv_packet()
            if resp_type == SERVERDATA_AUTH_RESPONSE:
                if resp_id == -1:
                    raise Exception("Неверный пароль")
                return
        raise Exception("Сервер не ответил на авторизацию")

    def send_command(self, command):
        if self.sock is None:
            self.connect()

        self.req_id += 1
        cmd_id = self.req_id

        self._send_packet(cmd_id, SERVERDATA_EXECCOMMAND, command)

        self.sock.settimeout(0.3)
        response = ""
        try:
            while True:
                rid, rtype, body = self._recv_packet()
                if rid != cmd_id:
                    continue
                if rtype == SERVERDATA_RESPONSE_VALUE:
                    response += body
                else:
                    break
        except socket.timeout:
            pass
        finally:
            self.sock.settimeout(5)

        return response.strip()

    def _send_packet(self, req_id, packet_type, payload):
        data = payload.encode("utf-8") + b"\x00"
        packet = struct.pack("<ii", req_id, packet_type) + data + b"\x00"
        full = struct.pack("<i", len(packet)) + packet
        self.sock.sendall(full)

    def _recv_packet(self):
        length_data = self._recv_exact(4)
        length = struct.unpack("<i", length_data)[0]
        body = self._recv_exact(length)
        req_id, rtype = struct.unpack("<ii", body[:8])
        payload = body[8:-2].decode("utf-8", errors="replace")
        return req_id, rtype, payload

    def _recv_exact(self, size):
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise Exception("Соединение прервано")
            data += chunk
        return data

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None


# Удобная функция для быстрого вызова без создания объекта
def send_rcon_command(host, port, password, command):
    client = RCONClient(host, port, password)
    try:
        client.connect()
        return client.send_command(command)
    finally:
        client.close()
