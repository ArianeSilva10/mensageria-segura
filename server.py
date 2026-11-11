import socket
import threading
import uuid
from protocolo import enviar_mensagem, receber_mensagem, enviar_frame, receber_frame, MSG_NOVO_PEER, MSG_PEER_SAIU, MSG_E2E, OVERHEAD_E2E
from criptografia import gerar_salt, carregar_certificado, calcular_hash_handshake, assinar_dados, montar_frame_admin
from cryptography.hazmat.primitives import serialization

HOST = "127.0.0.1"
PORT = 5000
certificado = carregar_certificado('.\\certificado.crt')
certificado_pem = certificado.public_bytes(serialization.Encoding.PEM)

with open('.\\certificado.key', 'rb') as arq:
    chavePrivadaServidor = serialization.load_pem_private_key(
        arq.read(),
        password=None
    )
clientes = {}
lock_clientes = threading.Lock()        #trava de seguranca pra evitar cindicoes de corrida

#envia um frame a um cliente, serializado os envios no mesmo socket
def enviar_para(dados, tipo, payload):
    with dados["lock_envio"]:
        enviar_frame(dados["conn"], tipo, payload)

#quem chama ja deve estar com dados ["lock_envio"], envia avisos de saiu nono...
def enviar_adm_sem_lock(dados, tipo, payload):
    seq = dados["seq_send"]
    dados["seq_send"] += 1
    corpo  = montar_frame_admin(chavePrivadaServidor, tipo, seq, dados["salt"], payload)
    enviar_frame(dados["conn"], tipo, corpo)

#chama a funcao anterior fazendo o envio
def enviar_adm(dados, tipo, payload):
    with dados["lock_envio"]:
        enviar_adm_sem_lock(dados, tipo, payload)

#encaminha as mensagens de chat criptografadas de ponta a ponta entre os clientes
def rotear_e2e(remetente_id, payload):
    if len(payload) < OVERHEAD_E2E:
        raise ValueError("frame E2E menor que o minimo")

    sender_id = payload[12:28]          #fatiamente de 16 bytes
    recipient_id = payload[28:44]

    if sender_id != remetente_id:
        raise ValueError("sender_id difere do cliente da conexao")

    with lock_clientes:
        destino = clientes.get(recipient_id)
    if destino is None:
        print("destinatario nao conectado; frame descartado")
        return

    try:
        enviar_para(destino, MSG_E2E, payload)
        print(f"frame E2E encaminhado ({len(payload)} bytes)")
    except (ConnectionError, OSError) as e:
        print(f"erro ao encaminar: {e}")

##################################################################
def atender_cliente(conn, addr):
    client_id_bytes = None
    print(f"cliente conectado: {addr}")
    registrado = False

    try:
        client_id_bytes = receber_mensagem(conn)

        if client_id_bytes is None:
            return

        if len(client_id_bytes) != 16:
            print("identificador invalido")
            return

        #recebe a chave puclica efemera
        pk_client = receber_mensagem(conn)
        if pk_client is None:
            return
        if len(pk_client) != 32:
            print("chave publica invalida")
            return
        print(f"cliente {uuid.UUID(bytes=client_id_bytes)} enviou chave publica ({len(pk_client)} bytes)")

        #criptografio do handshake
        salt = gerar_salt()
        hash_handshake = calcular_hash_handshake(certificado, pk_client, client_id_bytes, salt)

        assinatura = assinar_dados(chavePrivadaServidor, hash_handshake)

        lock_envio = threading.Lock()
        dados = {
            "conn": conn,
            "pk_client": pk_client,
            "salt": salt,
            "lock_envio": lock_envio,
            "seq_send": 0,
            "seq_recv": -1
        }
        with lock_envio:
            with lock_clientes:
                #lista de clientes ja conectados na sala
                outros = [(i, d) for i, d, in clientes.items() if i != client_id_bytes]
                
                antigo = clientes.get(client_id_bytes)
                clientes[client_id_bytes] = dados
                registrado = True
                print("clientes conectados:", len(clientes))

        enviar_mensagem(conn, certificado_pem)
        enviar_mensagem(conn, salt)
        enviar_mensagem(conn, assinatura)

        enviar_mensagem(conn, len(outros).to_bytes(4, byteorder="big"))
        for id_outro, d in outros:
            enviar_adm_sem_lock(dados, MSG_NOVO_PEER, id_outro + d["pk_client"] + d["salt"])

        print("handshake e lista de clientes enviados")

        if antigo is not None:
            print("reconexao com o mesmo client_id: sessao anterior encerrada")
            try:
                antigo["conn"].shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        #anuncia novo cliente aos que ja estavam conectados
        anuncio = client_id_bytes + pk_client + salt
        for id_outro, d in outros:
            try:
                enviar_adm(d, MSG_NOVO_PEER, anuncio)
            except (ConnectionError, OSError) as e:
                print(f"erro ao notificar cliente: {e}")

        while True:
            tipo, payload = receber_frame(conn)
            if tipo is None:
                break
            if tipo == MSG_E2E:
                rotear_e2e(client_id_bytes, payload)
            else:
                raise ValueError(f"tipo inesperado vindo do cliente: {tipo}")

    except (ConnectionError, OSError, ValueError, UnicodeDecodeError) as erro:
        print(f"erro na conexao com {addr}: {erro}")

    finally:
        if registrado:
            saiu = False
            with lock_clientes:
                atual = clientes.get(client_id_bytes)
                if atual is not None and atual["conn"] is conn:
                    del clientes[client_id_bytes]
                    saiu = True
                restantes = list(clientes.values())

            if saiu:
                for d in restantes:
                    try:
                        enviar_adm(d, MSG_PEER_SAIU, client_id_bytes)
                    except (ConnectionError, OSError):
                        pass
        conn.close()
        print(f"conexao encerrada: {addr}")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))
server.listen()

print(f"Servidor aguardando conexoes em {HOST}:{PORT}")

while True:
    conn,addr = server.accept()
    thread = threading.Thread(
        target=atender_cliente,
        args=(conn, addr)
    )

    thread.start()