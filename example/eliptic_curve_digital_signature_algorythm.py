from ecdsa import SigningKey, VerifyingKey, NIST384p

# Geração de um par de chaves
private_key = SigningKey.generate(curve=NIST384p)  # Gera a chave privada
public_key = private_key.get_verifying_key()       # Obtém a chave pública

# Dados a serem assinados
message = b"Transaction: Alice paga 10 BTC para Bob"

# Assinatura dos dados
signature = private_key.sign(message)

# Verificação da assinatura
is_valid = public_key.verify(signature, message)

print("Assinatura:", signature.hex())
print("Assinatura válida?", is_valid)

# Geração de um par de chaves
second_private_key = SigningKey.generate(curve=NIST384p)  # Gera a chave privada
second_public_key = second_private_key.get_verifying_key()       # Obtém a chave pública

# second_signature = second_private_key.sign(message)

print(f"Test: {second_public_key.verify(signature, message)}")
