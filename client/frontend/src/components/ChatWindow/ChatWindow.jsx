import { useState } from "react";
import {
  Avatar,
  Box,
  IconButton,
  Paper,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import LockOutlinedIcon from "@mui/icons-material/LockOutlined";
import SendRoundedIcon from "@mui/icons-material/SendRounded";
import VerifiedUserRoundedIcon from "@mui/icons-material/VerifiedUserRounded";

export default function ChatWindow({
  contact,
  messages,
  onSend,
  onSafetyNumber,
}) {
  const [text, setText] = useState("");
  if (!contact)
    return (
      <Box className="empty-chat">
        <LockOutlinedIcon />
        <Typography variant="h6">Sua caixa de mensagens privadas</Typography>
        <Typography color="text.secondary">
          Escolha um contato para começar com segurança.
        </Typography>
      </Box>
    );

  const send = async (event) => {
    event.preventDefault();
    if (!text.trim()) return;
    await onSend(text);
    setText("");
  };

  return (
    <Box className="chat-window">
      <Stack
        className="chat-header"
        direction="row"
        alignItems="center"
        justifyContent="space-between"
      >
        <Stack direction="row" alignItems="center" spacing={1.5}>
          <Avatar>{contact.slice(0, 2).toUpperCase()}</Avatar>
          <Box>
            <Typography fontWeight={700}>{contact}</Typography>
            <Typography variant="caption" color="success.main">
              Conversa protegida
            </Typography>
          </Box>
        </Stack>
        <Tooltip title="Ver Safety Number">
          <IconButton onClick={onSafetyNumber}>
            <VerifiedUserRoundedIcon />
          </IconButton>
        </Tooltip>
      </Stack>
      <Box className="messages">
        {messages.length === 0 && (
          <Typography className="chat-hint">
            As mensagens desta conversa são armazenadas localmente e cifradas
            antes do envio.
          </Typography>
        )}
        {messages.map((message, index) => (
          <MessageBubble
            key={`${message.timestamp ?? index}-${index}`}
            message={message}
          />
        ))}
      </Box>
      <Box component="form" onSubmit={send} className="composer">
        <TextField
          fullWidth
          size="small"
          placeholder="Escreva uma mensagem..."
          value={text}
          onChange={(event) => setText(event.target.value)}
        />
        <IconButton color="primary" type="submit" disabled={!text.trim()}>
          <SendRoundedIcon />
        </IconButton>
      </Box>
    </Box>
  );
}

function MessageBubble({ message }) {
  const outgoing = Boolean(
    message.is_sender ?? (message.sender === "me" || message.from_me),
  );
  return (
    <Box className={`message-row ${outgoing ? "outgoing" : "incoming"}`}>
      <Paper className="message-bubble" elevation={0}>
        <Typography>
          {message.content ?? message.text ?? message.message ?? ""}
        </Typography>
        {message.timestamp && (
          <Typography variant="caption" className="message-time">
            {new Date(message.timestamp).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            })}
          </Typography>
        )}
      </Paper>
    </Box>
  );
}
