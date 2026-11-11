#criar a identidade do servidor
#RSA-PSS

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

from datetime import datetime, timedelta, timezone

#crio o par de chaves (publica e privada)- 2^{16} + 1 = 65537
#tamanho da chave >= 2048
chave_privada = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

#ele eh atrelado nome/dominio (localhost)
nome_servidor = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
])


certificado = (
    x509.CertificateBuilder()
    .subject_name(nome_servidor)                    # quem pertence
    .issuer_name(nome_servidor)                     #quem emitiu
    .public_key(chave_privada.public_key())         #chave publica que foi criada
    .serial_number(x509.random_serial_number())     #numero de serie aleatorio(unico)
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))      #prazo que expira
    .sign(private_key=chave_privada, algorithm=hashes.SHA256())     #assinatura do servidor com a chave privada e SHA-256(autenticidade)
)

#exporta chave secreta
with open("certificado.key", "wb") as arq:
    arq.write(
        chave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,            # Base64
            format=serialization.PrivateFormat.PKCS8,       #formatacao de chaves
            encryption_algorithm=serialization.NoEncryption()   #sem senha
        )
    )


#exporta certificado com a chave publica
with open("certificado.crt", "wb") as arq:
    arq.write(
        certificado.public_bytes(
            encoding=serialization.Encoding.PEM #mesma base
        )
    )

print("Certificado gerado com sucesso")
print("Chave privada gerada com sucesso: certificado.key")
print("Certificado gerado com sucesso: certificado.crt")
print("tamanho da chave RSA:", 2048, "bits")