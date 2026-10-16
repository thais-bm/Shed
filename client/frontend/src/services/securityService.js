import { apiClient } from "./apiClient.js";

/*
Busca o Safety Number (impressão digital de 6 blocos numéricos) de uma conversa segura.

Retorno esperado da API:
{safety_number: "12345 67890 ..."}

@param {string} contato
@returns {Promise<string>}
*/
export async function buscarSafetyNumber(contato) {
  if (typeof contato !== "string" || !contato.trim()) {
    throw new Error("Informe um contato válido.");
  }

  const resultado = await apiClient.get(
    `/chat/safety-number/${encodeURIComponent(contato)}`,
  );

  if (typeof resultado?.safety_number !== "string") {
    throw new Error("A API retornou um Safety Number em formato inválido.");
  }

  return resultado.safety_number;
}
