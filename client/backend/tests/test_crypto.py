# client/backend/tests/test_crypto.py
from backend.crypto import ECDHManager
from backend.audit import SecurityAuditor

def test_alice_e_bob_derivam_o_mesmo_segredo_compartilhado():
    print("\n") # Quebra de linha para separar o log do cabeçalho do pytest
    SecurityAuditor.log_step("TESTE", "Iniciando teste de handshake ECDH...")
    
    # 1. Instanciar os clientes
    alice = ECDHManager()
    bob = ECDHManager()
    
    # 2. Gerar chaves locais
    alice_priv, alice_pub = alice.generate_key_pair()
    bob_priv, bob_pub = bob.generate_key_pair()
    
    # 3. Exportar para simular envio pela rede
    alice_pub_pem = alice.export_public_key(alice_pub)
    bob_pub_pem = bob.export_public_key(bob_pub)
    
    # 4. Importar as chaves públicas recebidas
    alice_imported_bob_pub = alice.load_public_key(bob_pub_pem)
    bob_imported_alice_pub = bob.load_public_key(alice_pub_pem)
    
    # 5. Derivar a chave simétrica final
    alice_symmetric_key = alice.derive_sym_key(alice_priv, alice_imported_bob_pub)
    bob_symmetric_key = bob.derive_sym_key(bob_priv, bob_imported_alice_pub)
    
    # 6. Asserção do pytest (Garante que a matemática não falhou)
    assert alice_symmetric_key == bob_symmetric_key
    assert len(alice_symmetric_key) == 32 # Garante que a chave tem 256 bits (32 bytes)
    
    SecurityAuditor.log_step("TESTE", "Sucesso: Ambas as chaves simétricas coincidem perfeitamente.")