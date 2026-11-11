# TP3 — Sistema de Mensageria Segura Multi-Cliente (E2E)

Disciplina: Segurança da Informação — Prof. Michel Sales

Servidor atua **somente como relay**: nunca possui chave que decifre mensagens entre clientes.

## Arquivos

| Arquivo | Função |
|---|---|
| `gerar_certificado.py` | Gera par RSA-2048 e certificado autoassinado (`certificado.key`, `certificado.crt`) |
| `criptografia.py` | X25519, HKDF-SHA256, AES-128-GCM, nonce/AAD, anti-replay, RSA-PSS, certificado pinado |
| `protocolo.py` | Framing TCP (prefixo de 4 bytes), tipos de mensagem, limites de tamanho |
| `server.py` | Handshake autenticado, tabela `clientes`, anúncio de peers, relay de frames E2E |
| `client.py` | Handshake, tabela `peers`, derivação de chaves, envio/recebimento E2E, menu |
| `teste_modulo.py`, `teste_25519.py` | Testes unitários das primitivas |
| `teste_ataques.py` | Testes offline das garantias de segurança (30 verificações) |

## Como executar

```
python gerar_certificado.py     # uma vez
python server.py
python client.py                # um terminal por cliente
```

Comandos do cliente: `/lista`, `/msg <início do id> <texto>`, `/sair`.
Com `DEMO = True` no `client.py`: `/adulterar`, `/replay`, `/framing grande`, `/framing curto`.

## Protocolo

### 1. Handshake (cliente ↔ servidor)

1. Cliente envia `client_id` (UUID v4, 16 B) e `pk_client` (X25519 raw, 32 B).
2. Servidor gera `salt` (16 B) e calcula `H = SHA256(pk_server || pk_client || client_id || salt)`.
   `pk_server` é a chave pública RSA em DER (SubjectPublicKeyInfo), pois RSA não tem formato "raw".
3. Servidor envia `server.crt`, `salt` e `RSA-PSS(SHA256)(H)`.
4. Cliente valida (a) o certificado pelo **fingerprint SHA-256 pinado** e (b) a assinatura de `H`.
   Isso impede MITM no registro das chaves públicas.
5. Servidor envia a lista dos clientes já conectados; cada um como frame
   `MSG_NOVO_PEER = client_id(16) | pk(32) | salt(16)`, e anuncia o novo cliente aos antigos.

### 2. Derivação das chaves E2E (cada par)

```
Z_AB     = X25519(sk_A, pk_B)                       # nunca trafega, nunca é logado
salt_par = SHA256(ordenado(id_A||salt_A, id_B||salt_B))[:16]
PRK      = HKDF-Extract(salt_par, Z_AB)
Key_A2B  = HKDF-Expand(PRK, "A2B", 16)
Key_B2A  = HKDF-Expand(PRK, "B2A", 16)
```

- Como cada cliente recebe um `salt` próprio do servidor, os dois salts são combinados
  deterministicamente (`calcular_salt_par`), sem nova troca pela rede.
- O cliente de **menor `client_id`** é o "A": os dois lados concordam sobre quem usa qual chave
  para enviar, mantendo as direções separadas.
- `Z_AB` é descartado após a derivação (existe só dentro de `registrar_peer`).

### 3. Frame E2E

```
tipo(1) = MSG_E2E | nonce(12) | sender_id(16) | recipient_id(16) | seq_no(8) | ciphertext + tag(16)
nonce = IV_base(4, aleatório por sessão/direção) || seq_no(8, big-endian)
AAD   = sender_id | recipient_id | seq_no
```

- Overhead E2E: 68 bytes (+1 de tipo). Plaintext máximo: 4096 bytes.
- Todo frame no TCP é prefixado por 4 bytes (big-endian) com o tamanho. O servidor rejeita
  tamanho acima do máximo **antes** de ler o corpo.

### 4. Envio e recebimento

- **Envio:** o `seq_send` é consumido antes de enviar (um seq nunca é reutilizado).
- **Relay:** o servidor lê só `sender_id`/`recipient_id`, confere que `sender_id` é o dono da conexão
  e repassa os bytes. Não decifra.
- **Recebimento:** valida tamanho, destinatário, remetente conhecido e coerência `nonce[4:] == seq_no`;
  confere `seq_no > último`; decifra (tag GCM); **só então** atualiza o contador.
  Frame adulterado não consome número de sequência.

### 5. Reconexão

Ao reconectar com o mesmo `client_id`, o handshake completo é refeito: novo `salt`, novas chaves
efêmeras, `seq` zerado, novo `IV_base`.

## Estruturas de dados

**Servidor** `clientes[client_id] = {conn, pk_client, salt, lock_envio, seq_send, seq_recv}`
- `lock_clientes` protege a tabela; `lock_envio` serializa escritas no mesmo socket
  (várias threads enviam ao mesmo cliente).

**Cliente** `peers[client_id] = {public_key, key_send, key_recv, seq_send, antireplay, iv_base_send, iv_base_recv}`
- `iv_base_recv` é aprendido no primeiro frame válido e fixado depois.

## Garantias e mecanismos

| Garantia | Mecanismo |
|---|---|
| Confidencialidade | AES-128-GCM com chaves E2E; servidor não as possui |
| Integridade | Tag GCM sobre ciphertext + AAD (ids e seq) |
| Autenticidade do servidor | Certificado RSA pinado + assinatura RSA-PSS sobre `H` |
| Sigilo perfeito | ECDHE X25519 efêmero; a RSA só assina, não entra na derivação |
| Anti-replay | `seq_no` monotônico por direção, checado no destinatário |
| Separação de direções | `A2B` ≠ `B2A`; reflexão de frame é rejeitada |

## Testes (apresentação)

| Teste | Como mostrar | Resultado esperado |
|---|---|---|
| Troca E2E | `/msg` entre 2 clientes | Destinatário decifra; terceiro cliente não vê nada |
| Bitflip | `/adulterar` | Destinatário: tag GCM inválida; mensagem seguinte é aceita |
| Replay | `/replay` | Mostra uma vez; cópia rejeitada por seq |
| Framing inválido | `/framing grande`, `/framing curto` | Servidor desconecta com erro |
| Garantias offline | `python teste_ataques.py` | 30/30 verificações |

## Política de logs

Registrados: conexão/desconexão, `client_id`, tamanhos de frame, motivo de rejeição,
fingerprints de chave (apenas para depuração).
**Nunca** registrados: chaves privadas, `Z`, `salt`, nonces, conteúdo de mensagens.

## Limitações conhecidas (para discussão)

- Depois do handshake, os frames administrativos do servidor (`MSG_NOVO_PEER`, `MSG_PEER_SAIU`)
  trafegam sem autenticação própria; um atacante ativo na rede poderia tentar injetar uma
  chave pública falsa. Mitigação possível: assinar cada anúncio com a chave RSA do servidor
  ou comparar fingerprints das chaves dos pares por outro canal.
- `client_id` não é autenticado: quem conectar com um id já em uso substitui a sessão anterior.
- Os campos `seq_send`/`seq_recv` do servidor estão na tabela conforme o enunciado, mas hoje
  não protegem mensagens administrativas.
- O servidor enxerga metadados (quem fala com quem, tamanhos, horários), nunca o conteúdo.