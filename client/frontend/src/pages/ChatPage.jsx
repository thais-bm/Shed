import { useCallback, useEffect, useState } from "react";
import { Alert, Box, Snackbar } from "@mui/material";
import { useNavigate } from "react-router-dom";
import ChatWindow from "../components/ChatWindow/ChatWindow.jsx";
import SafetyNumberDialog from "../components/SafetyNumberDialog/SafetyNumberDialog.jsx";
import Sidebar from "../components/Sidebar/Sidebar.jsx";
import { usePolling } from "../hooks/usePolling.js";
import {
  aceitarAmizade,
  buscarAmigos,
  buscarHistorico,
  buscarSafetyNumber,
  buscarUsuarios,
  enviarMensagem,
  iniciarChat,
  recusarAmizade,
  sair,
  solicitarAmizade,
} from "../services/index.js";
import "../App.css";

const emptyFriends = { friends: [], pendingReceived: [], pendingSent: [] };

export default function ChatPage() {
  const navigate = useNavigate();
  const username = sessionStorage.getItem("shed.username");
  const [data, setData] = useState(emptyFriends);
  const [activeContact, setActiveContact] = useState("");
  const [messages, setMessages] = useState([]);
  const [searchResults, setSearchResults] = useState([]);
  const [notice, setNotice] = useState("");
  const [safety, setSafety] = useState({ open: false, value: "" });

  const loadFriends = useCallback(async () => {
    try {
      setData(await buscarAmigos());
    } catch (error) {
      setNotice(error.message);
    }
  }, []);

  const loadMessages = useCallback(async () => {
    if (!activeContact) return;
    try {
      setMessages(await buscarHistorico(activeContact));
    } catch (error) {
      setNotice(error.message);
    }
  }, [activeContact]);

  useEffect(() => {
    if (!username) {
      navigate("/login", { replace: true });
      return;
    }
    const timer = window.setTimeout(() => { void loadFriends(); }, 0);
    return () => window.clearTimeout(timer);
  }, [loadFriends, navigate, username]);

  useEffect(() => {
    const timer = window.setTimeout(() => { void loadMessages(); }, 0);
    return () => window.clearTimeout(timer);
  }, [loadMessages]);

  usePolling(loadFriends, 15000, Boolean(username));
  usePolling(loadMessages, 3000, Boolean(activeContact));

  if (!username) return null;

  const selectContact = async (contact) => {
    setActiveContact(contact);
    setMessages([]);
    try {
      await iniciarChat(contact);
    } catch (error) {
      setNotice(error.message);
    }
  };

  const send = async (text) => {
    try {
      await enviarMensagem(activeContact, text);
      await loadMessages();
    } catch (error) {
      setNotice(error.message);
    }
  };

  const showSafetyNumber = async () => {
    setSafety({ open: true, value: "" });
    try {
      const value = await buscarSafetyNumber(activeContact);
      setSafety({ open: true, value });
    } catch (error) {
      setSafety({ open: false, value: "" });
      setNotice(error.message);
    }
  };

  const runFriendAction = async (action, contact) => {
    try {
      await action(contact);
      await loadFriends();
      setNotice("Lista de contatos atualizada.");
    } catch (error) {
      setNotice(error.message);
    }
  };

  const logout = async () => {
    try {
      await sair();
    } catch (error) {
      setNotice(error.message);
      return;
    }
    sessionStorage.removeItem("shed.username");
    navigate("/login", { replace: true });
  };

  return (
    <Box className="app-shell">
      <Sidebar
        username={username}
        friends={data.friends}
        pendingReceived={data.pendingReceived}
        activeContact={activeContact}
        onSelect={selectContact}
        searchResults={searchResults}
        onSearch={async (query) => {
          try {
            setSearchResults(await buscarUsuarios(query));
          } catch (error) {
            setNotice(error.message);
          }
        }}
        onAdd={(contact) => runFriendAction(solicitarAmizade, contact)}
        onAccept={(contact) => runFriendAction(aceitarAmizade, contact)}
        onReject={(contact) => runFriendAction(recusarAmizade, contact)}
        onLogout={logout}
      />
      <ChatWindow
        contact={activeContact}
        messages={messages}
        onSend={send}
        onSafetyNumber={showSafetyNumber}
      />
      <SafetyNumberDialog
        open={safety.open}
        contact={activeContact}
        safetyNumber={safety.value}
        onClose={() => setSafety({ ...safety, open: false })}
      />
      <Snackbar
        open={Boolean(notice)}
        autoHideDuration={5000}
        onClose={() => setNotice("")}
      >
        <Alert severity="info" onClose={() => setNotice("")}>{notice}</Alert>
      </Snackbar>
    </Box>
  );
}
