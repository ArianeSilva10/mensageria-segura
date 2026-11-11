#teste offline do protocolo de mensageria segura (sem rede e sem servidor)

import os, uuid, socket, struct
from cryptography.exceptions import InvalidTag
from criptografia import (gerar_chaves, exportar_chave_publica, calcular_segredo_compartilhado, gerar_salt, derivar_chaves, calcular_salt_par, criptografar_mensagem_protocolo, descriptografar_mensagem_protocolo, gerar_nonce, ControleAntiReplay, descriptografar_antireplay, abrir_frame_admin, montar_frame_admin)
from protocolo import receber_mensagem, enviar_mensagem, MAX_PLAIN_TEXT, OVERHEAD_E2E, MSG_NOVO_PEER, MSG_PEER_SAIU
from cryptography.hazmat.primitives.asymmetric import rsa   

resultados =[]

def checar(nome, condicao):
    resultados.append(bool(condicao))
    print(f"[{'OK' if condicao else 'FALHOU'}] {nome}")

#retorna true se a funcao levantar a excecao esperada
def rejeita(funcao, excecao):
    try:
        funcao()
    except excecao:
        return True
    return False

def novo_cliente():
    sk, pk = gerar_chaves()
    return {"sk": sk, "pk": exportar_chave_publica(pk), "id": uuid.uuid4().bytes, "salt": gerar_salt()}

#igual a registra_peer do client.py retorna key_send, key_recv
def chaves(eu, outro):
    segredo = calcular_segredo_compartilhado(eu["sk"], outro["pk"])
    salt_par = calcular_salt_par(eu["id"], eu["salt"], outro["id"], outro["salt"])
    a2b, b2a  =derivar_chaves(segredo, salt_par)
    return (a2b, b2a) if eu["id"] < outro["id"] else (b2a, a2b)

def cifrar(chave, texto, iv_base, de, para, seq):
    return criptografar_mensagem_protocolo(chave, texto, iv_base, de["id"], para["id"], seq)


A, B, C = novo_cliente(), novo_cliente(), novo_cliente()
a_send, a_recv = chaves(A, B)
b_send, b_recv = chaves(B, A)
iv_base = os.urandom(4)



##################################teste 1: ##########################################
print("\n1) derivacao de chaves entre A e B")
checar("A e B derivam as mesmas chaves (send de um = recv do outro)", a_send == b_recv and a_recv == b_send)
checar("chave de envio diferente da de recebimento", a_send != a_recv)

################################# teste 2: #######################

print("\n2) só o destinatario decifra")
segredoTexto = b"segredo de A para B"
frame = cifrar(a_send, segredoTexto, iv_base, A,B, 0)
texto = descriptografar_mensagem_protocolo(b_recv, frame, iv_base, A["id"],B["id"], 0)
checar("B decifra corretamente" , texto == segredoTexto)

c_com_a = chaves(C, A)
c_com_b = chaves(C, B)
tentativa = {
    "C com chave C-A (send)": c_com_a[0],
    "C com chave C-A (recv)": c_com_a[1],
    "C com chave C-b (send)": c_com_b[0],
    "C com chave C-B (recv)": c_com_a[1],
    "servidor com chave aleatoria": os.urandom(16)
}

for nome, k in tentativa.items():
    checar(f"{nome} NAO decifra", rejeita(lambda k=k: descriptografar_mensagem_protocolo(k, frame, iv_base, A["id"], B["id"], 0), InvalidTag))
checar("o texto claro nao aparece no frame cifrado", segredoTexto not in frame)


###################### teste 3: #########################
print("\n3) adulteracao (bitflip) em cada regiao do frame")
adulterado = bytearray(frame)
adulterado[0] ^= 0x01
checar("bit no ciphertext => tag invalida", rejeita(lambda: descriptografar_mensagem_protocolo(b_recv, bytes(adulterado), iv_base, A["id"], B["id"], 0), InvalidTag))

adulterado = bytearray(frame)
adulterado[-1] ^= 0x01
checar("bit na tag => tag invalida", rejeita(lambda: descriptografar_mensagem_protocolo(b_recv, bytes(adulterado), iv_base, A["id"], B["id"], 0), InvalidTag))

checar("sender_id trocado (AAD) => tag invalida", rejeita(lambda:descriptografar_mensagem_protocolo(b_recv ,frame, iv_base, C["id"], B["id"], 0), InvalidTag))
checar("recipient_id trocado (AAD) => tag invalida", rejeita(lambda: descriptografar_mensagem_protocolo(b_recv, frame, iv_base, A["id"], C["id"], 0), InvalidTag))
checar("seq_no trocado (AAD e nonce) => tag invalida", rejeita(lambda:descriptografar_mensagem_protocolo(b_recv, frame, iv_base, A["id"], B["id"], 1), InvalidTag))
checar("iv_base trocado (nonce) => tag invalida", rejeita(lambda:descriptografar_mensagem_protocolo(b_recv, frame, os.urandom(4), A["id"], B["id"], 0), InvalidTag))

############################## teste 4: #####################
print("\n4) reflexao: devolver ao remetente o frame que ele mesmo enviou")
checar("A nao aceita de volta o proprio frame (direcoes separadas)", rejeita(lambda: descriptografar_mensagem_protocolo(a_recv, frame, iv_base, A["id"], B["id"], 0), InvalidTag))
checar("A nao aceita o frame bem com ids invertidos", rejeita(lambda:descriptografar_mensagem_protocolo(a_recv, frame, iv_base, B["id"], A["id"], 0), InvalidTag))

############################# teste 5: ########################
print("\n5) anti-replay")
controle = ControleAntiReplay()
f0 = cifrar(a_send, b"msg 0", iv_base, A, B, 0)
f1 = cifrar(a_send, b"msg 1", iv_base, A, B, 1)
f2 = cifrar(a_send,b"msg 2", iv_base, A, B, 2)

def receber(f, seq):
    return descriptografar_antireplay(b_recv, f, iv_base, A["id"], B["id"], seq, controle)

checar("seq 0 aceito", receber(f0, 0) == b"msg 0")
checar("seq 1 aceito", receber(f1, 1) == b"msg 1")
checar("replay do seq 1 rejeitado", rejeita(lambda: receber(f1, 1), ValueError))
checar("replay so seq 0 (fora de ordem) rejeitado", rejeita(lambda: receber(f0, 0), ValueError))

f2_ruim = bytearray(f2)
f2_ruim[0] ^= 0x01
checar("frame seq 2 adulterado rejeitado", rejeita(lambda: receber(bytes(f2_ruim), 2), InvalidTag))
checar("...e NAO consumiu o seq 2: o frame legitimo ainda eh aceito", receber(f2,2) == b"msg 2")

nonces = {gerar_nonce(iv_base, s) for s in range(1000)}
checar("1000 nonces seguidos sao todos distintos", len(nonces) == 1000)

######################### teste 6 #########################
print("\n6) sigilo perfeito (chaves efemeras)")
A2, B2 = novo_cliente(), novo_cliente()
sessao1 = chaves(A, B)
sessao2 = chaves(A2, B2)
checar("duas sessoes (novos pares efemeros) geram chaves diferentes", sessao1[0] != sessao2[0])
# a chave RSA do servidor so assina o handshake; ela nao eh a entrada do HKDF
# a derivacao usa apenas ECDH + salt. Por isso comprometer a RSA no futuro
#nao revela as chaves de sessoes passadas

####################### teste 7: #########################
print("\n7) limite de tamaho e framing")
grande = os.urandom(MAX_PLAIN_TEXT)
f_max = cifrar(a_send, grande, iv_base, A, B, 10)
payload_max = os.urandom(12) + A["id"] + (10).to_bytes(8, "big") + f_max
checar("payload E2E com 4096 bytes de texto = MAX_PAIN_TEXT + OVERHEAD_E2E (68 BYTES)", len(payload_max) == MAX_PLAIN_TEXT + OVERHEAD_E2E)

max_frame = 1 + OVERHEAD_E2E + MAX_PLAIN_TEXT
a, b = socket.socketpair()
enviar_mensagem(a, b"x" * max_frame)
checar("frame com plaintext maximo (4096) eh aceito pelo framing", len(receber_mensagem(b)) == max_frame)
a.close();b.close()

a, b = socket.socketpair()
a.sendall(struct.pack("!I", max_frame+1))
checar("frame maior que o maximo => ValueError (desconexao segura)", rejeita(lambda: receber_mensagem(b), ValueError))
a.close(); b.close()

a, b = socket.socketpair()
a.sendall(struct.pack("!I", 100000) + b"x" * 10)
checar("prefixo declarado 100000 bytes => ValueError antes de ler o corpo", rejeita(lambda: receber_mensagem(b), ValueError))
a.close(); b.close()

a, b = socket.socketpair()
a.sendall(struct.pack("!I", 10) + b"abc")
a.close()
checar("conexao cortada no meio do frame => ConnectionError", rejeita(lambda: receber_mensagem(b), ConnectionError))
b.close()

############################ teste 8:
# simula a emissao de anuncios de novos peers
print("\n8) Frames administrativos do servidor (anúncios de peers assinados)")

rsa_servidor = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pk_servidor = rsa_servidor.public_key()
salt_sessao = gerar_salt()
anuncio = C["id"] + C["pk"] + C["salt"]       # NOVO_PEER anunciando o cliente C
corpo = montar_frame_admin(rsa_servidor, MSG_NOVO_PEER, 0, salt_sessao, anuncio)
 
 
def abrir(corpo_, tipo=MSG_NOVO_PEER, salt_=None, esperado=0, pk=None):
    return abrir_frame_admin(pk or pk_servidor, tipo, corpo_, salt_ or salt_sessao, esperado)
 
 
checar("tamanho do corpo = seq(8) + payload(64) + assinatura(256)", len(corpo) == 8 + 64 + 256)
checar("anúncio legítimo é aceito e o payload sai intacto", abrir(corpo) == anuncio)
 
forjado = bytearray(corpo)
forjado[8 + 16] ^= 0x01                        # 1 bit da chave pública anunciada
checar("chave pública do peer alterada em trânsito => rejeitada",
       rejeita(lambda: abrir(bytes(forjado)), ValueError))
checar("tipo trocado (NOVO_PEER → PEER_SAIU) => rejeitado",
       rejeita(lambda: abrir(corpo, tipo=MSG_PEER_SAIU), ValueError))
checar("frame de OUTRA sessão (salt diferente) => rejeitado",
       rejeita(lambda: abrir(corpo, salt_=gerar_salt()), ValueError))
checar("replay do mesmo anúncio (seq já usado) => rejeitado",
       rejeita(lambda: abrir(corpo, esperado=1), ValueError))
corpo_adiantado = montar_frame_admin(rsa_servidor, MSG_NOVO_PEER, 5, salt_sessao, anuncio)
checar("seq adiantado (frames suprimidos no caminho) => rejeitado",
       rejeita(lambda: abrir(corpo_adiantado), ValueError))
rsa_atacante = rsa.generate_private_key(public_exponent=65537, key_size=2048)
corpo_atacante = montar_frame_admin(rsa_atacante, MSG_NOVO_PEER, 0, salt_sessao, anuncio)
checar("anúncio assinado por outra chave RSA (atacante) => rejeitado",
       rejeita(lambda: abrir(corpo_atacante), ValueError))
checar("frame truncado => rejeitado",
       rejeita(lambda: abrir(corpo[:20]), ValueError))
 

######################################
print(f"\nresumo: {sum(resultados)}/{len(resultados)} testes passaram")
raise SystemExit(0 if all(resultados) else 1)