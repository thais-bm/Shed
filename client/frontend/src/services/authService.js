import { apiClient } from "./apiClient.js";

export async function entrar(username, password) {
  return apiClient.post("/auth/login", {
    username: normalizeUsername(username),
    password,
  });
}

export async function cadastrar(username, password) {
  return apiClient.post("/auth/register", {
    username: normalizeUsername(username),
    password,
  });
}

export async function sair() {
  return apiClient.post("/auth/logout");
}

function normalizeUsername(username) {
  return username.trim().toLowerCase();
}
