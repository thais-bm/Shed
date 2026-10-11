
/*
Configurações do ambiente.

O endereço pode ser alterado no arquivo .env do Vite,
sem precisar modificar os serviços ou os componentes.

*/

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8001";

export const env = Object.freeze({
  API_BASE_URL: API_BASE_URL.replace(/\/+$/, ""),
});
