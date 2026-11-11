from criptografia import (
    gerar_chaves,
    exportar_chave_publica,
    importar_chave_publica,
    calcular_segredo_compartilhado,
    gerar_salt,
    derivar_chaves,
    criptografar_mensagem,
    descriptografar_mensagem,
    gerar_nonce,
    gerar_aad, 
    criptografar_mensagem_protocolo,
    descriptografar_mensagem_protocolo,
    ControleAntiReplay,
    descriptografar_antireplay,
    assinar_dados,
    verificar_assinatura,
    carregar_certificado,
    verificar_certificado,
    calcular_hash_handshake,
    calcular_salt_par,
)
import os, uuid
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509

chavePrivada_a, chavePublica_a = gerar_chaves()
chavePrivada_b, chavePublica_b = gerar_chaves()

privada_a, publica_a = gerar_chaves()
privada_b, publica_b = gerar_chaves()

publica_a_bytes = exportar_chave_publica(publica_a)
publica_b_bytes = exportar_chave_publica(publica_b)

publica_a_importada = importar_chave_publica(publica_a_bytes)
publica_b_importada = importar_chave_publica(publica_b_bytes)

pk_a = exportar_chave_publica(chavePublica_a)
pk_b = exportar_chave_publica(chavePublica_b)

segredo_a = calcular_segredo_compartilhado(privada_a, pk_b)
segredo_b = calcular_segredo_compartilhado(privada_b, pk_a)

print("Tamanho da chave pública A:", len(publica_a_bytes), "bytes")
print("Tamanho da chave pública B:", len(publica_b_bytes), "bytes")
print("Os segredos compartilhados são iguais?", segredo_a == segredo_b)

salt = gerar_salt()

chave_a2b, chave_b2a = derivar_chaves(segredo_a, salt)

a_envia_b = chave_a2b
a_recebe_b = chave_b2a
b_envia_a = chave_b2a
b_recebe_a = chave_a2b

print("\nTeste HKDF-SHA256:")
print("tamanho do salt:", len(salt), "bytes")
print("tamanho das chaves derivadas:", len(chave_a2b), "bytes")
print("chaves de envio compativeis?", a_envia_b == b_recebe_a)
print("chaves de recebimento compativeis?", a_recebe_b == b_envia_a)
print("chaves de envio diferentes das de recebimento?", a_envia_b != a_recebe_b)

print("\nTeste AES-GCM:")
mensagem = "ola cliente B! Mensagem secreta".encode("utf-8")
nonce = os.urandom(12)
aad = b"dados autenticados adicionais"

mensagem_cifrada = criptografar_mensagem(chave_a2b, mensagem, nonce, aad)
mensagem_decifrada = descriptografar_mensagem(chave_a2b, mensagem_cifrada, nonce, aad)

print("Mensagem original:", mensagem.decode("utf-8"))
print("Mensagem cifrada:", mensagem_cifrada.hex())
print("Mensagem decifrada:", mensagem_decifrada.decode("utf-8"))
print("A mensagem decifrada é igual à original?", mensagem == mensagem_decifrada)
print("Tamanho do nonce:", len(nonce), "bytes")
print("tamanho da chave:", len(chave_a2b), "bytes")

print("\nTeste de integridade com AAD:")

mensagem_adulterada = bytearray(mensagem_cifrada)
mensagem_adulterada[0] ^= 0x01

try:
    descriptografar_mensagem(chave_a2b, bytes(mensagem_adulterada), nonce, aad)
    print("Falha: A mensagem adulterada foi descriptografada com sucesso!")
except InvalidTag:
    print("Sucesso: A mensagem adulterada foi detectada como inválida!")



################# teste do nonce e aad gerados automaticamente #################
print("\nTeste de Nonce e AAD gerados automaticamente:")
sender_id = uuid.uuid4().bytes
receiver_id = uuid.uuid4().bytes
seq_no = 0

iv_base = os.urandom(4)
nonce = gerar_nonce(iv_base, seq_no)
aad = gerar_aad(sender_id, receiver_id, seq_no)

print("Tamanho do sender_id:", len(sender_id))
print("Tamanho do receiver_id:", len(receiver_id))
print("Tamanho do IV_base:", len(iv_base))
print("Tamanho do nonce:", len(nonce))
print("Tamanho do AAD:", len(aad))

######################## teste do protocolo completo ########################
print("\nTeste do protocolo completo:")
mensagem_protocolo = "Mensagem do protocolo".encode("utf-8")

sender_id = uuid.uuid4().bytes
receiver_id = uuid.uuid4().bytes

iv_base = os.urandom(4)
seq_no = 0

mensagem_cifrada_protocolo = criptografar_mensagem_protocolo(a_envia_b, mensagem_protocolo, iv_base, sender_id, receiver_id, seq_no)
mensagem_decifrada_protocolo = descriptografar_mensagem_protocolo(b_recebe_a, mensagem_cifrada_protocolo, iv_base, sender_id, receiver_id, seq_no)

print("Mensagem original do protocolo:", mensagem_protocolo.decode("utf-8"))
print("Mensagem cifrada do protocolo:", mensagem_cifrada_protocolo.hex())
print("Mensagem decifrada do protocolo:", mensagem_decifrada_protocolo.decode("utf-8"))
print("A mensagem decifrada do protocolo é igual à original?", mensagem_protocolo == mensagem_decifrada_protocolo)



########################## teste do controle anti-replay ##########################
print("\nTeste do controle anti-replay:")
controle_anti_replay = ControleAntiReplay()
sequencias_teste = [0, 1, 1, 0, 2]

for seq in sequencias_teste:
    try:
        controle_anti_replay.verificar_replay(seq)
        controle_anti_replay.atualizar(seq)
        print(f"Sequência {seq} aceita.")
    except ValueError as e:
        print(f"Sequência {seq} rejeitada: {e}")


####################### teste do protocolo completo com controle anti-replay #######################
print("\nTeste do protocolo completo com controle anti-replay:")
controle = ControleAntiReplay()
seq_no = 0
mensagem_cifrada_protocolo = criptografar_mensagem_protocolo(a_envia_b, mensagem_protocolo, iv_base, sender_id, receiver_id, seq_no)

original = descriptografar_antireplay(b_recebe_a, mensagem_cifrada_protocolo, iv_base, sender_id, receiver_id, seq_no, controle)
print("Mensagem decifrada com controle anti-replay:", original.decode("utf-8"))

###### segunda tentativa com a mesma sequência, deve falhar
try:
    original = descriptografar_antireplay(b_recebe_a, mensagem_cifrada_protocolo, iv_base, sender_id, receiver_id, seq_no, controle)
    print("Falha: A mensagem foi decifrada novamente com a mesma sequência!")
except ValueError as e:
    print("Sucesso: A mensagem não foi decifrada novamente com a mesma sequência:", e)


################## teste de adulteração da mensagem com controle anti-replay ##################
print("\nTeste de adulteração da mensagem com controle anti-replay:")
controle = ControleAntiReplay()
seq_no = 0
iv_base = os.urandom(4)
mensagem0 = criptografar_mensagem_protocolo(a_envia_b, mensagem_protocolo, iv_base, sender_id, receiver_id, seq_no)

descriptografar_antireplay(b_recebe_a, mensagem0, iv_base, sender_id, receiver_id, seq_no, controle)

print("sequencia 0: aceita")

mensagem1 = criptografar_mensagem_protocolo(a_envia_b, mensagem_protocolo, iv_base, sender_id, receiver_id, seq_no + 1)

mensagem_adulterada = bytearray(mensagem1)
mensagem_adulterada[0] ^= 0x01

try:
    descriptografar_antireplay(b_recebe_a, bytes(mensagem_adulterada), iv_base, sender_id, receiver_id, seq_no + 1, controle)
    print("Falha: A mensagem adulterada foi decifrada com sucesso!")
except InvalidTag as e:
    print("Sucesso: A mensagem adulterada não foi decifrada:", e)

try:
    original = descriptografar_antireplay(b_recebe_a, mensagem1, iv_base, sender_id, receiver_id, seq_no + 1, controle)
    print("Sequencia 1 legitima: ", original.decode("utf-8"))
    
except InvalidTag as e:
    print("Falha: A mensagem não foi decifrada:", e)

################ teste de certificado autoassinado ################
print("\nTeste de certificado RSA:")

with open("certificado.crt", "rb") as arq:
    certificado = x509.load_pem_x509_certificate(arq.read())

chave_publica = certificado.public_key()

print("Tipo da chave: ", type(chave_publica).__name__)
print("Tamanho da chave: ", chave_publica.key_size, "bits")
print("Nome do servidor: ", certificado.subject)
print("Certificado autoassinado: ", certificado.subject == certificado.issuer)


############### teste de assinatura e verificação de dados ###############
print("\nTeste de assinatura e verificação de dados:")

with open("certificado.key", "rb") as arq:
    chave_privada = serialization.load_pem_private_key(arq.read(), password=None)

with open("certificado.crt", "rb") as arq:
    certificado = x509.load_pem_x509_certificate(arq.read())
chave_publica = certificado.public_key()

dados = b"Dados a serem assinados"
assinatura = assinar_dados(chave_privada, dados)
resultado = verificar_assinatura(chave_publica, dados, assinatura)

print("Assinatura gerada:", len(assinatura), "bytes")
print("Assinatura válida:", resultado)

dados_adulterados = b"Dados adulterados"
resultado_adulterado = verificar_assinatura(chave_publica, dados_adulterados, assinatura)
print("Assinatura válida para dados adulterados:", resultado_adulterado)

############## teste de verificação de certificado ##############
print("\nTeste de verificação de certificado:")
certificado = carregar_certificado("certificado.crt")
print("Certificado carregado com sucesso.")

print("Tipo da chave pública do certificado:", type(certificado.public_key()).__name__)
print("certificado carregado com sucesso: ", certificado is not None)
print("Tamanho da chave pública do certificado:", certificado.public_key().key_size, "bits")

##################### teste de verificação de certificado autoassinado #####################
print("\nTeste de verificação de certificado autoassinado:")
certificado_cliente = carregar_certificado("certificado.crt")
certificado_servidor = carregar_certificado("certificado.crt")

resultado_verificacao = verificar_certificado(certificado_cliente, certificado_servidor)
print("Certificado autoassinado verificado com sucesso:", resultado_verificacao)

###########################  teste do handshake completo com certificado autoassinado ###########################
print("\nTeste do handshake completo com certificado autoassinado:")
certificado = carregar_certificado("certificado.crt")
chave_privada_cliente, chave_publica_cliente = gerar_chaves()
pk_client = exportar_chave_publica(chave_publica_cliente)

client_id = uuid.uuid4().bytes
salt = gerar_salt()

hash_handshake = calcular_hash_handshake(certificado, pk_client, client_id, salt)

with open("certificado.key", "rb") as arq:
    chave_privada_servidor = serialization.load_pem_private_key(arq.read(), password=None)

assinatura = assinar_dados(chave_privada_servidor, hash_handshake)

chave_publica_servidor = certificado.public_key()
assinatura_valida = verificar_assinatura(chave_publica_servidor, hash_handshake, assinatura)

hash_handshake_adulterado = bytearray(hash_handshake)
hash_handshake_adulterado[0] ^= 0x01

assinatura_alterada_valida = verificar_assinatura(chave_publica_servidor, bytes(hash_handshake_adulterado), assinatura)
print("tamanho da assinatura:", len(assinatura), "bytes")
print("Assinatura válida: ", assinatura_valida)
print("Assinatura apos a alteracao:", assinatura_alterada_valida)

print("Tamanho da chave pública do cliente:", len(pk_client), "bytes")
print("Tamanho do client_id:", len(client_id), "bytes")
print("Tamanho do salt:", len(salt), "bytes")
print("Tamanho do hash:", len(hash_handshake), "bytes")


######## teste de salt por par
id_a = b"A" * 16
id_b = b"B" * 16

salt_a = b"1" * 16
salt_b = b"2" * 16

salt_clienteA = calcular_salt_par(id_a, salt_a, id_b, salt_b)
salt_clienteB = calcular_salt_par(id_b, salt_b, id_a, salt_a)

print("salt dos dois clientes eh igual: ", salt_clienteA == salt_clienteB)
print("tamanho do salt: ", len(salt_clienteA))


########## teste de calculo de chaves publicas entre clientes
chavePrivada_a, chavePublica_a = gerar_chaves()
chavePrivada_b, chavePublica_b = gerar_chaves()

pk_a = exportar_chave_publica(chavePublica_a)
pk_b = exportar_chave_publica(chavePublica_b)

segredo_a = calcular_segredo_compartilhado(chavePrivada_a, pk_b)
segredo_b = calcular_segredo_compartilhado(chavePrivada_b, pk_a)

print("tamanho do segredo A: ", len(segredo_a))
print("tamanho do segredo B: ", len(segredo_b))
print("segredos compartilhados sao iguais: ", segredo_a == segredo_b)

############ teste de ECDH + HKDF entre clientes

salt_a = gerar_salt()
salt_b = gerar_salt()

id_a = uuid.uuid4().bytes
id_b = uuid.uuid4().bytes

salt_par_a = calcular_salt_par(id_a, salt_a, id_b, salt_b)
salt_par_b = calcular_salt_par(id_b, salt_b, id_a, salt_a)

chave_a2b_a, chave_b2a_a = derivar_chaves(segredo_a, salt_par_a)
chave_a2b_b, chave_b2a_b = derivar_chaves(segredo_b, salt_par_b)

print("\nteste ECDH + HKDF: ")
print("salts iguais: ", salt_par_a == salt_par_b)
print("chaves A2B iguais: ", chave_a2b_a == chave_a2b_b)
print("chaves B2A iguais: ", chave_b2a_a == chave_b2a_b)
print("chave bidirecionais diferentes: ", chave_a2b_a != chave_b2a_a)