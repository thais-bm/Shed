import { env } from "../config/env.js";

/* Erros são padronizados */
export class ApiError extends Error {
  constructor(message, { status = 0, detail = null } = {}) {
    super(message);

    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

//Tempo de Time out
const TIMEOUT_MS = 10_000;

/*
Realiza uma requisição HTTP à API local.

@param {string} path - Caminho do endpoint.
@param {RequestInit} options - Opções do fetch.
@returns {Promise<any>} Dados retornados pela API.

*/
async function request(path, options = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const headers = new Headers(options.headers);

    if (options.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }

    headers.set("Accept", "application/json");

    const response = await fetch(`${env.API_BASE_URL}${path}`, {
      ...options,
      headers,
      signal: controller.signal,
    });

    const contentType = response.headers.get("content-type");
    let data = null;

    if (response.status !== 204) {
      if (contentType?.includes("application/json")) {
        data = await response.json();
      } else {
        data = await response.text();
      }
    }

    if (!response.ok) {
      const detail =
        typeof data === "object" && data !== null
          ? (data.detail ?? data.message)
          : data;

      const message =
        typeof detail === "string" && detail.trim()
          ? detail
          : `A API retornou o erro HTTP ${response.status}.`;

      throw new ApiError(message, {
        status: response.status,
        detail: data,
      });
    }

    return data;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }

    if (error.name === "AbortError") {
      throw new ApiError("A requisição demorou demais. Tente novamente.");
    }

    throw new ApiError(
      "Não foi possível conectar à API local. Verifique se o backend está funcionando.",
    );
  } finally {
    clearTimeout(timeoutId);
  }
}

export const apiClient = Object.freeze({
  get(path) {
    return request(path, {
      method: "GET",
    });
  },

  post(path, body) {
    return request(path, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },
});
