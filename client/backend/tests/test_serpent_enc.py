# client/backend/tests/test_serpent_enc.py
import pytest
from backend.serpent_enc import SerpentProtocol
from backend.audit import SecurityAuditor

def test_cifragem_e_decifragem_com_sucesso():
    """Teste do Caminho Feliz: Alice envia, Bob recebe e decifra com a mesma chave."""
    print("\n")
    SecurityAuditor.log_step("TESTE", "Iniciando teste de Cifragem/Decifragem...")
    
    # Simulamos uma chave de sessão de 32 bytes (256 bits) gerada pelo ECDH
    chave_sessao = b'\x01' * 32 
    
    alice = SerpentProtocol(chave_sessao)
    bob = SerpentProtocol(chave_sessao)
    
    mensagem_original = "Shed: Teste de Criptografia com Serpent e HMAC!"
    
    # Alice cifra
    pacote = alice.encrypt_message(mensagem_original)
    
    # Bob decifra
    mensagem_decifrada = bob.decrypt_message(pacote)
    
    # Garante que a mensagem final é exatamente igual à original
    assert mensagem_decifrada == mensagem_original

def test_falha_de_integridade_mensagem_adulterada():
    """Teste de Segurança: Simula um hacker alterando 1 byte da mensagem na rede."""
    print("\n")
    SecurityAuditor.log_step("TESTE", "Iniciando teste de Defesa HMAC (Hacker na rede)...")
    
    chave_sessao = b'\x02' * 32 
    alice = SerpentProtocol(chave_sessao)
    bob = SerpentProtocol(chave_sessao)
    
    pacote_original = alice.encrypt_message("Transferir $100 para Bob")
    
    # Transformamos em bytearray para podermos modificar um byte (simulando o hacker)
    pacote_hacker = bytearray(pacote_original)
    # O hacker altera o primeiro byte do pacote (parte do IV ou da Cifra)
    pacote_hacker[0] = pacote_hacker[0] ^ 0xFF 
    
    # O Bob tenta decifrar o pacote adulterado. 
    # O pytest.raises garante que o nosso código VAI disparar um ValueError.
    with pytest.raises(ValueError, match="Falha na validação do HMAC"):
        bob.decrypt_message(bytes(pacote_hacker))
        
    SecurityAuditor.log_step("TESTE", "Sucesso! O sistema bloqueou a mensagem adulterada.")

def test_rejeita_pacote_muito_pequeno():
    """Teste de Validação: O sistema deve rejeitar pacotes que não tenham o tamanho mínimo."""
    chave_sessao = b'\x03' * 32 
    bob = SerpentProtocol(chave_sessao)
    
    # Pacote com apenas 10 bytes (o mínimo exigido são 48 bytes: 16 de IV + 32 de MAC)
    pacote_invalido = b'\x00' * 10
    
    with pytest.raises(ValueError, match="Pacote corrompido ou muito pequeno"):
        bob.decrypt_message(pacote_invalido)