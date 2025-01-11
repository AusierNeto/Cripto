from ecdsa import SigningKey, NIST384p
from classes.Transaction import Transaction


if __name__ == "__main__":
    # Gerar pares de chaves (privada e pública)
    sender_private_key = SigningKey.generate(curve=NIST384p)
    sender_public_key = sender_private_key.get_verifying_key()

    recipient_private_key = SigningKey.generate(curve=NIST384p)
    recipient_public_key = recipient_private_key.get_verifying_key()

    # Criar uma transação
    transaction = Transaction(
        sender_public_key=sender_public_key.to_string().hex(),
        recipient_public_key=recipient_public_key.to_string().hex(),
        amount=10
    )

    # Assinar a transação
    transaction.sign_transaction(sender_private_key)
    print("Transação assinada:", transaction.signature.hex())

    # Verificar a transação
    is_valid = transaction.is_valid()
    print("A transação é válida?", is_valid)

    second_operator_private_key = SigningKey.generate(curve=NIST384p)
    second_operator_public_key = second_operator_private_key.get_verifying_key()

    new_transaction = Transaction(
        sender_public_key=recipient_public_key.to_string().hex(),
        recipient_public_key=second_operator_public_key.to_string().hex(),
        amount=5,
        last_transaction_hash=transaction.last_transaction_hash
    )

    new_transaction.sign_transaction(recipient_private_key)
    print("Nova transação assinada:", new_transaction.signature.hex())

    is_valid = new_transaction.is_valid()
    print("A nova transação é válida?", is_valid)
