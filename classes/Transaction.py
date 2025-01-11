import hashlib
import json

from ecdsa import VerifyingKey, NIST384p


class Transaction:
    def __init__(self, sender_public_key, recipient_public_key, amount, last_transaction_hash=None):
        self.sender_public_key = sender_public_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount
        self.signature = None
        self.last_transaction_hash = last_transaction_hash

    def to_dict(self):
        # Representa a transação como um dicionário (necessário para hashing)
        return {
            'sender': self.sender_public_key,
            'recipient': self.recipient_public_key,
            'amount': self.amount,
            'last_transaction_hash': self.last_transaction_hash
        }

    def sign_transaction(self, sender_private_key):
        # Assina a transação usando a chave privada do remetente
        self.hash_transaction()
        self.signature = sender_private_key.sign(self.last_transaction_hash.encode())

    def hash_transaction(self):
        # Gera um hash único para a transação
        transaction_str = json.dumps(self.to_dict(), sort_keys=True)
        self.last_transaction_hash = hashlib.sha256(transaction_str.encode()).hexdigest()

    def is_valid(self):
        # Verifica a assinatura da transação usando a chave pública do remetente
        if self.signature is None:
            raise ValueError("Transação não assinada.")
        
        verifying_key = VerifyingKey.from_string(bytes.fromhex(self.sender_public_key), curve=NIST384p)
        return verifying_key.verify(self.signature, self.last_transaction_hash.encode())