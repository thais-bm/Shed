import { apiClient } from "./apiClient.js";

/*
Busca o histórico de uma conversa.

Retorno esperado:
{history: [...]}

@param {string} contato
@returns {Promise<Array>}
*/
export async function buscarHistorico(contato) {
  if (typeof contato !== "string" || !contato.trim()) {
    throw new Error("Informe um contato válido.");
  }

  const resultado = await apiClient.get(
    `/chat/history/${encodeURIComponent(contato)}`,
  );

  if (!Array.isArray(resultado?.history)) {
    throw new Error("A API retornou um histórico em formato inválido.");
  }

  return resultado.history;
}
