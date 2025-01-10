import hashlib
import json

from ecdsa import VerifyingKey, NIST384p


class Transaction:
    def __init__(self, sender_public_key, recipient_public_key, amount):
        self.sender_public_key = sender_public_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount
        self.signature = None

    def to_dict(self):
        # Representa a transação como um dicionário (necessário para hashing)
        return {
            'sender': self.sender_public_key,
            'recipient': self.recipient_public_key,
            'amount': self.amount,
        }

    def sign_transaction(self, sender_private_key):
        # Assina a transação usando a chave privada do remetente
        transaction_hash = self.hash_transaction()
        self.signature = sender_private_key.sign(transaction_hash.encode())

    def hash_transaction(self):
        # Gera um hash único para a transação
        transaction_str = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(transaction_str.encode()).hexdigest()

    def is_valid(self):
        # Verifica a assinatura da transação usando a chave pública do remetente
        if self.signature is None:
            raise ValueError("Transação não assinada.")
        transaction_hash = self.hash_transaction()
        verifying_key = VerifyingKey.from_string(bytes.fromhex(self.sender_public_key), curve=NIST384p)
        return verifying_key.verify(self.signature, transaction_hash.encode())