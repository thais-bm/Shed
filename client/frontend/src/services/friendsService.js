import { apiClient } from "./apiClient.js";

const contatoPath = (contato) => encodeURIComponent(contato.trim());

export async function buscarUsuarios(query) {
  if (!query.trim()) return [];
  const result = await apiClient.get(`/users/search?q=${encodeURIComponent(query.trim())}`);
  return Array.isArray(result) ? result : result?.users ?? [];
}

export async function buscarAmigos() {
  const result = await apiClient.get("/friends");
  return {
    friends: result?.friends ?? [],
    pendingReceived: result?.pending_received ?? result?.incoming_requests ?? [],
    pendingSent: result?.pending_sent ?? [],
  };
}

export function solicitarAmizade(contato) {
  return apiClient.post(`/friends/request/${contatoPath(contato)}`);
}

export function aceitarAmizade(contato) {
  return apiClient.post(`/friends/accept/${contatoPath(contato)}`);
}

export function recusarAmizade(contato) {
  return apiClient.post(`/friends/reject/${contatoPath(contato)}`);
}

export function removerAmigo(contato) {
  return apiClient.delete(`/friends/${contatoPath(contato)}`);
}
