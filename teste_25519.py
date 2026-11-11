import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import uuid


chave_privada_a = x25519.X25519PrivateKey.generate()
chave_publica_a = chave_privada_a.public_key()

chave_privada_b = x25519.X25519PrivateKey.generate()
chave_publica_b = chave_privada_b.public_key()

publica_a_bytes = chave_publica_a.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

publica_b_bytes = chave_publica_b.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

print("Cliente A:")
print(f"Tamanho da chave publica: {len(publica_a_bytes)} bytes")

print("\nCliente B:")
print(f"Tamanho da chave pública: {len(publica_b_bytes)} bytes")

segredo_a = chave_privada_a.exchange(chave_publica_b)

segredo_b = chave_privada_b.exchange(chave_publica_a)

print("\nSegredo compartilhado:")
print(f"Tamanho: {len(segredo_a)} bytes")
print(f"Tamanho: {len(segredo_a)} bytes")
print(f"Os segredos são iguais? {segredo_a == segredo_b}")

salt = os.urandom(16)

def derivar_chaves(segredo, salt, info):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        info=info
    )

    return hkdf.derive(segredo)

chave_a2b = derivar_chaves(
    segredo_a, salt, b"A2B"
)

chave_b2a = derivar_chaves(
    segredo_a, salt, b"B2A"
)

print("\n Derivação de chaves: ")
print(f"Key A2B: {len(chave_a2b)} bytes")
print(f"Key B2A: {len(chave_b2a)} bytes")
print(f"As chaves sao diferentes? {chave_a2b != chave_b2a}")

aes = AESGCM(chave_a2b)

nonce = os.urandom(12)

mensagem = "Ola, cliente B! Mensagem secreta".encode("utf-8")

mensagem_cifrada = aes.encrypt(
    nonce, mensagem, None
)

print("\nTeste AES-128-GCM:")
print(f"Tamanho do nonce: {len(nonce)} bytes")
print(f"Mensagem original: {mensagem.decode('utf-8')}")
print(f"Mensagem criptografada: {mensagem_cifrada.hex()}")

mensagem_original = aes.decrypt(
    nonce, mensagem_cifrada, None
)

print(f"Mensagem descriptograda: {mensagem_original.decode('utf-8')}")
print(f"Descriptografada correta? {mensagem_original == mensagem}")

# estrutura modificavel
mensagem_adulterada = bytearray(mensagem_cifrada)

#alterna primeiro bit do primeiro byte
mensagem_adulterada[0] ^= 1
print("\n teste de integridade: ")

try:
    aes.decrypt(
        nonce, 
        bytes(mensagem_adulterada),
        None
    )

    print("ERRO: mensagem adulterada foi aceita!")

except InvalidTag:
    print("SUCESSO: adulteração detectada")
    print("a autenticacao do AES-GCM rejeitou a mensagem")


########################## nonce e dados autenticados (AAD)

# id dos clientes 16 B
sender_id = uuid.uuid4().bytes
recipient_id = uuid.uuid4().bytes

# IV base de 4 bytes para esta direcao de comunicacao
iv_base = os.urandom(4)

# primeiro numero de sequencia
seq_no = 0

#converter o contador para 8 bytes em big-endian
seq_bytes = seq_no.to_bytes(8, byteorder="big")

#nonce de 12 bytes
nonce_protocolo = iv_base+seq_bytes

# dados adicionais autenticados AAD
aad = sender_id + recipient_id + seq_bytes

#criptografar usando chave A2B
aes_protocolo = AESGCM(chave_a2b)

mensagem = "mensage, seguindo o protocolo Vigia".encode("utf-8")

cifrada = aes_protocolo.encrypt(
    nonce_protocolo,
    mensagem,
    aad
)

#descriptografa
decifrada = aes_protocolo.decrypt(
    nonce_protocolo,
    cifrada,
    aad
)

print("\n teste do formato do protocolo:")
print(f"tamanho do sender_id: {len(sender_id)} bytes")
print(f"tamanho do recipient_id: {len(recipient_id)} bytes")
print(f"Tamanho do IV base: {len(iv_base)} bytes")
print(f"Tamanho do nonce: {len(nonce_protocolo)} bytes")
print(f"Tamanho do AAD: {len(aad)} bytes")
print(f"Sequência: {seq_no}")
print(f"Descriptografia correta? {decifrada == mensagem}")



############ simula controle de sequencia do destinatario
seq_recv = -1

def verificar_sequencia(seq_recebida):
    global seq_recv

    if seq_recebida <= seq_recv:
        raise ValueError("mensagem repetida ou fora de ordem")

    seq_recv = seq_recebida
    return True

print("\n teste antirreplay:")

#primeira mensagem : sequencia 0
print(f"sequencia 0 aceita? {verificar_sequencia(0)}")

#segunda mensagem sequencia 1
print(f"Sequencia 1 aceita? {verificar_sequencia(1)}")

#tentar reproduzir sequencia 0
try:
    verificar_sequencia(0)
    print("ERRO: mensagem repetida foi aceita")

except ValueError as erro:
    print(f"SUCESSO: {erro}")