/*
Ao invés de importar cada arquivo separadamente
Importa tudo daqui
Resolve o problemão que tive com importes no PratoMatch XD
*/

export { ApiError, apiClient } from "./apiClient.js";

export {
  iniciarChat,
  enviarMensagem,
  verificarConexao,
} from "./chatService.js";

export { buscarHistorico } from "./historyService.js";

export { buscarSafetyNumber } from "./securityService.js";

export { entrar, cadastrar, sair } from "./authService.js";

export {
  buscarUsuarios,
  buscarAmigos,
  solicitarAmizade,
  aceitarAmizade,
  recusarAmizade,
  removerAmigo,
} from "./friendsService.js";
