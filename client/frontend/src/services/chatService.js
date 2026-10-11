import { apiClient } from "./apiClient.js";

/*
Inicia uma conversa com um contato

O backend gera a sessão ECDH e envia a chave pública
ao relé. A sessão ainda pode estar aguardando resposta

@param {string} contato
*/
export async function iniciarChat(contato) {
  validarContato(contato);
  return apiClient.post(`/chat/start/${encodeURIComponent(contato)}`);
}

/*
Envia uma mensagem em texto simples para a API local

A criptografia Serpent e a validação do HMAC
são responsabilidadeas do backend
@param {string} contato
@param {string} texto
*/
export async function enviarMensagem(contato, texto) {
  validarContato(contato);

  if (typeof texto !== "string" || !texto.trim()) {
    throw new Error("Digite uma mensagem antes de enviar.");
  }

  return apiClient.post(`/chat/send/${encodeURIComponent(contato)}`, {
    text: texto,
  });
}

/*Verifica se a API local está respondendo*/
export async function verificarConexao() {
  return apiClient.get("/health");
}

/* Validação básica dos dados recebidos da interface*/
function validarContato(contato) {
  if (typeof contato !== "string" || !contato.trim()) {
    throw new Error("Informe um contato válido.");
  }
}
