import struct

MAX_PLAIN_TEXT = 4096
OVERHEAD_E2E = 12 + 16 + 8 + 16  # nonce + ids + seq + tag
MAX_FRAME = 1 + OVERHEAD_E2E + MAX_PLAIN_TEXT # 1 bytes de tipo

#tipo de mensagem - depois do handshake
MSG_NOVO_PEER = 1
MSG_PEER_SAIU = 2
MSG_E2E = 3

#lê todo o conteúdo durante o while ate atingir q quantidade de bytes especificada
def receber_bytes(conn, tamanho):
    dados = b""

    while len(dados) < tamanho:
        parte = conn.recv(tamanho-len(dados))

        if not parte:
            if len(dados) == 0:
                return None

            raise ConnectionError("conexao interrompida durante a mensagem")

        dados += parte
    return dados

#prepara e envia qualquer mensagem pela rede garantindo que o receptor saiba o tamanho exato dela
def enviar_mensagem(conn, mensagem):
    tamanho = len(mensagem)

    prefixo = struct.pack("!I", tamanho)        #converte o numero inteiro do tammanho em 4 bytes com prefixo "!I"

    conn.sendall(prefixo+mensagem)

#le os 4 bytes (prefixo) e ve depois os bytes do proximo pacote
def receber_mensagem(conn):
    prefixo = receber_bytes(conn, 4)

    if prefixo is None:
        return None

    tamanho = struct.unpack("!I", prefixo)[0]

    if tamanho > MAX_FRAME:
        raise ValueError("Mensagem excede o limite de 4096 bytes.")

    return receber_bytes(conn, tamanho)

#pega o tipo da mensagem e converte em byte unico e concatena na frente do payload
def enviar_frame(conn, tipo, payload=b""):
    enviar_mensagem(conn, bytes([tipo]) + payload)

#retorna (tipo, payload) ou (None, None) se a conexao fechou limpa
def receber_frame(conn):
    frame = receber_mensagem(conn)

    if frame is None:
        return None, None
    if len(frame) < 1:
        raise ValueError("frame vazio")
    return frame[0], frame[1:]