import { useState } from "react";
import {
  Avatar,
  Badge,
  Box,
  Button,
  Divider,
  IconButton,
  InputAdornment,
  List,
  ListItemButton,
  ListItemText,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import CheckRoundedIcon from "@mui/icons-material/CheckRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import LogoutRoundedIcon from "@mui/icons-material/LogoutRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import PersonAddAltRoundedIcon from "@mui/icons-material/PersonAddAltRounded";
import DarkModeRoundedIcon from "@mui/icons-material/DarkModeRounded";
import LightModeRoundedIcon from "@mui/icons-material/LightModeRounded";
import { useAppTheme } from "../../theme/ThemeContext.js";

const initials = (name) => name.slice(0, 2).toUpperCase();

export default function Sidebar({
  username,
  friends,
  pendingReceived,
  activeContact,
  onSelect,
  onSearch,
  searchResults,
  onAdd,
  onAccept,
  onReject,
  onLogout,
}) {
  const [query, setQuery] = useState("");
  const { mode, toggleMode } = useAppTheme();
  return (
    <Box className="sidebar">
      <Stack
        direction="row"
        alignItems="center"
        justifyContent="space-between"
        px={2.5}
        py={2}
      >
        <Stack direction="row" spacing={1.2} alignItems="center">
          <Avatar className="user-avatar">{initials(username)}</Avatar>
          <Box>
            <Typography fontWeight={700}>{username}</Typography>
            <Typography variant="caption" color="success.main">
              ● Online
            </Typography>
          </Box>
        </Stack>
        <Stack direction="row" spacing={0.5}>
          <Tooltip title={mode === "dark" ? "Usar modo claro" : "Usar modo escuro"}>
            <IconButton onClick={toggleMode} aria-label="Alternar tema">
              {mode === "dark" ? <LightModeRoundedIcon /> : <DarkModeRoundedIcon />}
            </IconButton>
          </Tooltip>
          <Tooltip title="Sair">
            <IconButton onClick={onLogout}>
              <LogoutRoundedIcon />
            </IconButton>
          </Tooltip>
        </Stack>
      </Stack>
      <Divider />
      <Box p={2}>
        <TextField
          fullWidth
          size="small"
          placeholder="Buscar pessoas"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            onSearch(event.target.value);
          }}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchRoundedIcon fontSize="small" />
              </InputAdornment>
            ),
          }}
        />
        {query && searchResults.length > 0 && (
          <PaperResults results={searchResults} onAdd={onAdd} />
        )}
      </Box>
      {pendingReceived.length > 0 && (
        <Box px={2} pb={1}>
          <Typography className="section-label">
            Solicitações{" "}
            <Badge color="primary" badgeContent={pendingReceived.length} />
          </Typography>
          {pendingReceived.map((contact) => (
            <Stack
              key={contact}
              direction="row"
              alignItems="center"
              spacing={1}
              py={0.7}
            >
              <Avatar sx={{ width: 30, height: 30 }}>
                {initials(contact)}
              </Avatar>
              <Typography variant="body2" flex={1}>
                {contact}
              </Typography>
              <IconButton
                size="small"
                color="success"
                onClick={() => onAccept(contact)}
              >
                <CheckRoundedIcon fontSize="small" />
              </IconButton>
              <IconButton
                size="small"
                color="error"
                onClick={() => onReject(contact)}
              >
                <CloseRoundedIcon fontSize="small" />
              </IconButton>
            </Stack>
          ))}
        </Box>
      )}
      <Box px={2}>
        <Typography className="section-label">Conversas</Typography>
      </Box>
      <List disablePadding sx={{ px: 1 }}>
        {friends.map((contact) => (
          <ListItemButton
            key={contact}
            selected={activeContact === contact}
            onClick={() => onSelect(contact)}
            sx={{ borderRadius: 2, mb: 0.5 }}
          >
            <Avatar
              sx={{
                mr: 1.5,
                bgcolor:
                  activeContact === contact
                    ? "primary.main"
                    : "action.selected",
              }}
            >
              {initials(contact)}
            </Avatar>
            <ListItemText
              primary={contact}
              secondary="Conversa segura"
              secondaryTypographyProps={{ variant: "caption" }}
            />
          </ListItemButton>
        ))}
        {friends.length === 0 && (
          <Typography color="text.secondary" variant="body2" px={2} py={2}>
            Adicione amigos para começar uma conversa.
          </Typography>
        )}
      </List>
    </Box>
  );
}

function PaperResults({ results, onAdd }) {
  return (
    <Box className="search-results">
      {results.map((user) => {
        const name = typeof user === "string" ? user : user.username;
        return (
          <Stack
            key={name}
            direction="row"
            alignItems="center"
            spacing={1}
            py={0.7}
          >
            <Avatar sx={{ width: 30, height: 30 }}>{initials(name)}</Avatar>
            <Typography variant="body2" flex={1}>
              {name}
            </Typography>
            <Button
              size="small"
              startIcon={<PersonAddAltRoundedIcon />}
              onClick={() => onAdd(name)}
            >
              Adicionar
            </Button>
          </Stack>
        );
      })}
    </Box>
  );
}
