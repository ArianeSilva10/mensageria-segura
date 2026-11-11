import uuid, threading, socket, os, hashlib, struct
from protocolo import enviar_mensagem, receber_mensagem, receber_frame, MSG_NOVO_PEER, MSG_PEER_SAIU, MSG_E2E, MAX_PLAIN_TEXT, enviar_frame, OVERHEAD_E2E
from criptografia import gerar_chaves, exportar_chave_publica, carregar_certificado, verificar_certificado, verificar_assinatura, calcular_hash_handshake, calcular_segredo_compartilhado, calcular_salt_par, derivar_chaves, ControleAntiReplay, gerar_nonce, criptografar_mensagem, descriptografar_antireplay, criptografar_mensagem_protocolo
from cryptography import x509
from cryptography.exceptions import InvalidTag


HOST = "127.0.0.1"
PORT = 5000
certificadoConfiavel = carregar_certificado('.\\certificado.crt')

client_id = uuid.uuid4()
client_id_bytes = client_id.bytes

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

peers = {}
lock_peers = threading.Lock()

def registrar_peer(payload, meu_id, minha_sk, meu_salt):
    if len(payload) != 64:
        raise ValueError("payload de peer invalido")
    id_peer, pk_peer, salt_peer = payload[:16], payload[16:48], payload[48:64]
    if id_peer == meu_id:
        raise ValueError("peer com o mesmo id do cliente")

    segredo = calcular_segredo_compartilhado(minha_sk, pk_peer)
    salt_par = calcular_salt_par(meu_id, meu_salt, id_peer, salt_peer)
    chave_a2b, chave_b2a = derivar_chaves(segredo, salt_par)

    #o menor client_id eh o "A": os dois lados chega à mesma conclusao
    if meu_id < id_peer:
        key_send, key_recv = chave_a2b, chave_b2a
    else:
        key_send, key_recv = chave_b2a, chave_a2b

    with lock_peers:
        peers[id_peer] = {
            "public_key": pk_peer,
            "key_send": key_send,
            "key_recv": key_recv,
            "seq_send": 0,
            "antireplay": ControleAntiReplay(),
            "iv_base_send": os.urandom(4),
            "iv_base_recv": None
        }

    fp_send = hashlib.sha256(key_send).hexdigest()[:8]
    fp_recv = hashlib.sha256(key_recv).hexdigest()[:8]
    print(f"chaves E2E com {uuid.UUID(bytes=id_peer)} (fp send={fp_send}, recv={fp_recv})")

def ouvir_servidor(conn, meu_id, minha_sk, meu_salt):
    while True:
        try:
            tipo, payload = receber_frame(conn)

            if tipo is None:
                print("servidor encerrou a conexao")
                break
            if tipo == MSG_NOVO_PEER:
                registrar_peer(payload, meu_id, minha_sk, meu_salt)
            elif tipo == MSG_PEER_SAIU:
                if len(payload) != 16:
                    raise ValueError("id invalido em PEER_SAIU")
                with lock_peers:
                    peers.pop(payload, None)
                print(f"cliente desconectado: {uuid.UUID(bytes=payload)}")
            elif tipo == MSG_E2E:
                tratar_e2e(payload, meu_id)
            else:
                raise ValueError(f"tipo de mensagem desconhecido: {tipo}")

        except (ConnectionError, OSError, ValueError) as e:
            print(f"erro ao receber atualizacao : {e}")
            break

def montar_frame_e2e(meu_id, id_peer,texto):
    if len(texto) > MAX_PLAIN_TEXT:
            raise ValueError(f"mensagem maior que {MAX_PLAIN_TEXT} bytes")
    
    with lock_peers:
        peer = peers.get(id_peer)
        if peer is None:
            raise ValueError("peer desconhecido")
        
        seq = peer["seq_send"]
        peer["seq_send"] += 1  # consome o seq antes de enviar, nunca reutiliza
        chave = peer["key_send"]
        iv_base = peer["iv_base_send"]
    
        nonce = gerar_nonce(iv_base, seq)
        cifrado = criptografar_mensagem_protocolo(chave, texto, iv_base, meu_id, id_peer, seq)
        payload = nonce + meu_id + id_peer + seq.to_bytes(8, "big") + cifrado
    return payload

def enviar_e2e(sock, meu_id, id_peer, texto):
    enviar_frame(sock, MSG_E2E, payload)

def achar_peer(prefixo):
    with lock_peers:
        candidatos = [pid for pid in peers
                      if str(uuid.UUID(bytes=pid)).startswith(prefixo)]
    return candidatos[0] if len(candidatos) == 1 else None

#qualquer rejeicao aqui, só descarta o frame; nao derruba a conexao
def tratar_e2e(payload, meu_id):
    try:
        if len(payload) < OVERHEAD_E2E:
            raise ValueError ("frame E2E menor que o minimo")
        nonce = payload[:12]
        sender_id = payload[12:28]
        recipient_id = payload[28:44]
        seq_bytes = payload[44:52]
        cifrado = payload[52:]

        if recipient_id != meu_id:
            raise ValueError("frame destinado a outro cliente")
        with lock_peers:
            peer = peers.get(sender_id)
        if peer is None:
            raise ValueError("remetente desconhecido")
        if nonce[4:] != seq_bytes:
            raise ValueError("nonce inconsistente com seq_no")

        iv_base = nonce[:4]
        if peer["iv_base_recv"] is not None and iv_base != peer["i_base_recv"]:
            raise ValueError("IV_base difere do aprendido")

        seq = int.from_bytes(seq_bytes, "big")
        texto = descriptografar_antireplay(peer["key_recv"], cifrado, iv_base, sender_id, meu_id, seq, peer["antireplay"])
        peer["iv_base_recv"] = iv_base
        print(f"\n[{str(uuid.UUID(bytes=sender_id))[:8]}] {texto.decode('utf-8', errors='replace')}")

    except InvalidTag:
        print("\nmensagem rejeitada: tag GCM invalida (adulterada ou chave errada)")
    except ValueError as e:
        print(f"\nmensagem rejeitada: {e}")


try: 
    client.connect((HOST, PORT))

    print("conectado ao servidor!")
    print(f"ID do cliente: {client_id}")

    enviar_mensagem(client, client_id_bytes)

    chavePrivadaCliente, chavePublicaCliente = gerar_chaves()
    pk_client = exportar_chave_publica(chavePublicaCliente)
    enviar_mensagem(client, pk_client)
    print("Chave pública do cliente enviada para o servidor.")

    certificado_bytes = receber_mensagem(client)
    salt = receber_mensagem(client)
    assinatura = receber_mensagem(client)
    print(f"certificado: {len(certificado_bytes)} bytes, salt: {len(salt)} bytes, assinatura: {len(assinatura)} bytes")

    certificadoRecebido = x509.load_pem_x509_certificate(certificado_bytes)
    certificadoValido = verificar_certificado(certificadoRecebido, certificadoConfiavel)
    print("certificado do servidor eh confiavel: ", certificadoValido)

    if not certificadoValido:
        print("certificado nao confiavel. Conexao encerrada")
        exit()

    hash_handshake = calcular_hash_handshake(certificadoRecebido, pk_client, client_id_bytes, salt)
    chavePublicaServidor = certificadoRecebido.public_key()
    assinaturaValida =verificar_assinatura(chavePublicaServidor, hash_handshake, assinatura)
    print("assinatura do servidor valida: ", assinaturaValida)
    if not assinaturaValida:
        print("assinatura invalida. Conexao encerrada")
        exit()

    quantidadeBytes = receber_mensagem(client)
    if quantidadeBytes is None or len(quantidadeBytes) != 4:
        raise ValueError("quantidade de clientes invalida")

    quantidadeClientes = int.from_bytes(quantidadeBytes, byteorder="big")

    print("outros clientes disponiveis: ", quantidadeClientes)

    for i in range(quantidadeClientes):
        tipo, payload = receber_frame(client)
        if tipo != MSG_NOVO_PEER:
            raise ValueError("esperava MSG_NOVO_PEER na lista inicial")

        registrar_peer(payload, client_id_bytes, chavePrivadaCliente, salt)
        
    thread_recv = threading.Thread(target=ouvir_servidor, args=(client, client_id_bytes, chavePrivadaCliente, salt), daemon=True)
    thread_recv.start()
    print("thread de recebimento inciada")

    print("Hancshake concluido") 
    print("comandos: /lista | /msg <id> <texto> | /sair")
    while True:
        linha = input("> ").strip()
        if linha == "/sair":
            break
        elif linha == "/lista":
            with lock_peers:
                for pid in peers:
                    print(" ", uuid.UUID(bytes=pid))
        elif linha.startswith("/msg "):
            partes = linha.split(" ", 2)
            if len(partes) < 3:
                print("uso: /msg <id> <texto>")
                continue
            pid = achar_peer(partes[1].lower())
            if pid is None:
                print("peer nao encontrado (ou id ambiguo)")
                continue
            try:
                enviar_e2e(client, client_id_bytes, pid, partes[2].encode("utf-8"))
            except ValueError as e:
                print(f"nao enviado: {e}")

        else:
            print("comando desconhecido")

except (ConnectionError, OSError, ValueError) as erro:
    print(f"Erro na comunicacao: {erro}")

finally:
    client.close()

