from cryptography.hazmat.primitives.asymmetric import x25519, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography  import x509
import os, hashlib

#troca de chaves efêmeras (ECDHE via curva X25519)

#retorna o par de chaves para o cliente,  Diffie-Hellman
def gerar_chaves():
    chave_privada = x25519.X25519PrivateKey.generate()      #gere a chave privada (32 bytes secretos) 256 bits
    chave_publica = chave_privada.public_key()              #a partir da privada, segra a publica


    return chave_privada, chave_publica

#converte a chave publica de 36 bytes em Raw em vez de PEM
def exportar_chave_publica(chave_publica):
    return chave_publica.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

#reconstroi o objeto de chave a partir dos 32 B recebidos do peer
def importar_chave_publica(chave_publica_bytes):
    if len(chave_publica_bytes) != 32:
        raise ValueError("A chave pública deve ter exatamente 32 bytes.")
    
    return x25519.X25519PublicKey.from_public_bytes(chave_publica_bytes)

#pega chave publica de demais e combina com a privada local que gera valor secreto comunm pra ambos
def calcular_segredo_compartilhado(chave_privada, pk_outroCliente):
    chave_publicaOutro = importar_chave_publica(pk_outroCliente)
    return chave_privada.exchange(chave_publicaOutro)  # multiplicacao X25519 ECDH


####### derivacao de chaves simetricas (HKDF-SHA256) #############
# retorna 16 B aleatorios usado no handshake
def gerar_salt():
    return os.urandom(16)

#transforma segredo bruto derivado da curva eliptica em duas chaves simetricas AES-128 (a2b, b2A)
def derivar_chaves(segredo, salt):
    hkdf_a2b = HKDF(
        algorithm=hashes.SHA256(),
        length=16,          #128 bits
        salt=salt,          #salt aleatorio gerado pelo servido
        info=b"A2B"
    )
    chave_a2b = hkdf_a2b.derive(segredo)        #passa os 32 bytes do segredo bruto para calcular o resultado final

    hkdf_b2a = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        info=b"B2A"
    )
    chave_b2a = hkdf_b2a.derive(segredo)

    return chave_a2b, chave_b2a

#retorna mensagem cifrada usando chave derivada, nonce e AAD, AAD (40B) = sender_id (16B) || recipient_id (16B) || seq_no (8B)
def criptografar_mensagem(chave, mensagem, nonce, aad):
    cipher = AESGCM(chave)
    return cipher.encrypt(nonce, mensagem, aad)

#decifra e verifica a tag de autenticacao
def descriptografar_mensagem(chave, mensagem_cifrada, nonce, aad):
    cipher = AESGCM(chave)
    return cipher.decrypt(nonce, mensagem_cifrada, aad)

#constroi o nonce de 12 bytes ; iv_base (4 bytes) || seq_no (8bytes)
def gerar_nonce(iv_base, seq_no):
    if len(iv_base) != 4:
        raise ValueError("O IV base deve ter exatamente 4 bytes.")
    
    seq_no_bytes = seq_no.to_bytes(8, byteorder='big')
    return iv_base + seq_no_bytes

#gera dados autenticados adicionais (aad): sender_id (16 bytes) || receiver_id (16 bytes)
def gerar_aad(sender_id, receiver_id, seq_no):
    if len(sender_id) != 16 or len(receiver_id) != 16:
        raise ValueError("Os IDs do remetente e do destinatário devem ter exatamente 16 bytes cada.")
    
    seq_no_bytes = seq_no.to_bytes(8, byteorder='big')
    return sender_id + receiver_id + seq_no_bytes

####################### juntar tudo em uma função de protocolo #######################
def criptografar_mensagem_protocolo(chave, mensagem, iv_base, sender_id, receiver_id, seq_no):
    nonce = gerar_nonce(iv_base, seq_no)
    aad = gerar_aad(sender_id, receiver_id, seq_no)
    mensagem_cifrada = criptografar_mensagem(chave, mensagem, nonce, aad)
    return mensagem_cifrada

####################### mesma coisa do anterior, só que descriptografa
def descriptografar_mensagem_protocolo(chave, mensagem_cifrada, iv_base, sender_id, receiver_id, seq_no):
    nonce = gerar_nonce(iv_base, seq_no)
    aad = gerar_aad(sender_id, receiver_id, seq_no)
    mensagem_decifrada = descriptografar_mensagem(chave, mensagem_cifrada, nonce, aad)
    return mensagem_decifrada

############ controle anti replay ######################
class ControleAntiReplay:
    def __init__(self):
        self.ultima_sequencia = -1

    def verificar_replay(self, sequencia_recebida):
        if sequencia_recebida <= self.ultima_sequencia:
            raise ValueError("Numero de sequência inválido: já foi recebido")

    #atualiza a ultima sequencia recebida
    def atualizar(self, sequencia_recebida):
        self.ultima_sequencia = sequencia_recebida

#combina a verificacao de replay com a descriptografia AES-GCM
def descriptografar_antireplay(chave, mensagem_cifrada, iv_base, sender_id, receiver_id, seq_no, controle_anti_replay):
    # Verifica o controle anti-replay
    controle_anti_replay.verificar_replay(seq_no)
    
    # Descriptografa a mensagem
    mensagem_decifrada = descriptografar_mensagem_protocolo(chave, mensagem_cifrada, iv_base, sender_id, receiver_id, seq_no)
    
    # Atualiza o controle anti-replay
    controle_anti_replay.atualizar(seq_no)
    return mensagem_decifrada

############### assinatura digitais e certificados (RSA-PSS e X5519) ################
#gera uma assinatura RSA-PSS com chave privada do servidor
def assinar_dados(chave_privada, dados):
    assinatura = chave_privada.sign(
        dados,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return assinatura

#valida a assinatura se bate com os dados e chave publica
def verificar_assinatura(chave_publica, dados, assinatura):
    try:
        chave_publica.verify(
            assinatura,
            dados,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# le o certificado e converte para obj x.509
def carregar_certificado(caminho_certificado):
    with open(caminho_certificado, "rb") as arq:
        certificado = x509.load_pem_x509_certificate(arq.read())
    return certificado

# calcula o hash do certificado vindo da rede e compara com o que carregou
def verificar_certificado(certificado_recebido, certificado_confiavel):
    fingerprint_recebido = certificado_recebido.fingerprint(hashes.SHA256())
    fingerprint_confiavel = certificado_confiavel.fingerprint(hashes.SHA256())
    return fingerprint_recebido == fingerprint_confiavel

#calcula h = SHA256(pk_server || pk_client || client_id || salt)
#assinado pelo servidor 
def calcular_hash_handshake(certificado, pk_client, client_id, salt):
    pk_server = certificado.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if len(pk_client) != 32:
        raise ValueError("O chave pública deve ter exatamente 32 bytes.")

    if len(client_id) != 16:
        raise ValueError("O client_id deve ter exatamente 16 bytes.")

    if len(salt) != 16:
        raise ValueError("O salt deve ter exatamente 16 bytes.")

    dados = pk_server + pk_client + client_id + salt
    digest = hashes.Hash(hashes.SHA256())
    digest.update(dados)
    return digest.finalize()


# calcular o mesmo salt sem precisar trocar um novo valor pela rede
#faz ordenacao de bytes com o mesmo salt de 16 bytes
def calcular_salt_par(id_a, salt_a, id_b, salt_b):
    if len(id_a) != 16 or len(id_b) != 16:
        raise ValueError("IDS devem possuir 16 bytes")
    if len(salt_a) != 16 or len(salt_b) != 16:
        raise ValueError("salts devem possuir 16 bytes")

    if id_a < id_b:
        dados = id_a + salt_a + id_b + salt_b
    else:
        dados = id_b + salt_b + id_a + salt_a

    return hashlib.sha256(dados).digest()[:16]


################ frames administrativos do servidor (autenticados) ################
# depois do handshake, o servidor ainda manda frames administrativos
# (MSG_NOVO_PEER, MSG_PEER_SAIU). Sem proteção, um atacante na rede poderia
# injetar uma chave pública falsa (MITM no E2E). Por isso cada frame é assinado
# com a chave RSA do servidor (a mesma do certificado pinado).
#
#   corpo = seq_no (8B) | payload | assinatura RSA-PSS
#   assinado = tipo (1B) | seq_no (8B) | salt da sessão do cliente (16B) | payload
#
# - seq_no: contador consecutivo por conexão (seq_send do servidor). Detecta
#   replay, reordenação e frames suprimidos.
# - salt da sessão: amarra a assinatura a ESTA sessão deste cliente, então um frame
#   capturado em outra sessão (inclusive do mesmo client_id) não valida.

#monta os bytes que serao assinados no frame de controle: tipo (1B) || seq_no (8B) || salt_sessao (16B) || payload.
def dados_assinados_admin(tipo, seq_no, salt_cliente, payload):
    if len(salt_cliente) != 16:
        raise ValueError("o sat deve ter exatamente 16 bytes")
    return bytes([tipo]) + seq_no.to_bytes(8, byteorder="big") + salt_cliente + payload


# servidor: devolve o corpo seq_no | payload | assinatura
def montar_frame_admin(chave_privadaServidor, tipo, seq_no, salt_cliente, payload):
    assinatura = assinar_dados(chave_privadaServidor, dados_assinados_admin(tipo, seq_no, salt_cliente,payload))
    return seq_no.to_bytes(8, byteorder="big") + payload + assinatura


# cliente valida assinatura e sequencia e devolve o payload. levanta ValueError se o frame for invalido
def abrir_frame_admin(chavepublicaServidor, tipo, corpo, salt_cliente, seq_esperado):
    tam_assinatura = chavepublicaServidor.key_size // 8
    if len(corpo) < 8 + tam_assinatura:
        raise ValueError("frame administrativo curto demais")

    seq_no = int.from_bytes(corpo[:8], byteorder="big")
    payload = corpo[8:-tam_assinatura]
    assinatura = corpo[-tam_assinatura:]

    dados = dados_assinados_admin(tipo, seq_no, salt_cliente, payload)
    if not verificar_assinatura(chavepublicaServidor, dados, assinatura):
        raise ValueError("assinatura invalida no frame administrativo")

    if seq_no != seq_esperado:
        raise ValueError("sequencia administrativa inesperada (repetida, fora de ordem ou frame perdido)")

    return payload