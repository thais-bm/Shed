import { useState } from "react";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Container,
  Link,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import LockRoundedIcon from "@mui/icons-material/LockRounded";

export default function AuthPage({ onSubmit, error }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ username: "", password: "" });
  const [loading, setLoading] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setLoading(true);
    try {
      await onSubmit(form, mode);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box className="auth-shell">
      <Container maxWidth="sm">
        <Paper className="auth-card" elevation={0}>
          <Box className="brand-mark">
            <LockRoundedIcon />
          </Box>
          <Typography variant="h4" fontWeight={800} gutterBottom>
            {mode === "login" ? "Bem-vindo ao Shed" : "Crie sua conta"}
          </Typography>
          <Typography color="text.secondary" mb={3}>
            Mensagens privadas, simples e protegidas ponta a ponta.
          </Typography>
          <Stack component="form" onSubmit={submit} spacing={2}>
            {error && <Alert severity="error">{error}</Alert>}
            <TextField
              label="Nome de usuário"
              value={form.username}
              onChange={(event) =>
                setForm({ ...form, username: event.target.value })
              }
              required
              inputProps={{
                minLength: 3,
                maxLength: 32,
                pattern: "[a-zA-Z0-9_.-]+",
              }}
              helperText="Use de 3 a 32 caracteres: letras, números, ponto, hífen ou sublinhado."
              autoComplete="username"
              autoFocus
            />
            <TextField
              label="Senha"
              type="password"
              value={form.password}
              onChange={(event) =>
                setForm({ ...form, password: event.target.value })
              }
              required
              inputProps={{ minLength: 6, maxLength: 128 }}
              helperText="A senha deve ter entre 6 e 128 caracteres."
              autoComplete={
                mode === "login" ? "current-password" : "new-password"
              }
            />
            <Button
              type="submit"
              variant="contained"
              size="large"
              disabled={loading}
            >
              {loading ? (
                <CircularProgress size={24} color="inherit" />
              ) : mode === "login" ? (
                "Entrar"
              ) : (
                "Cadastrar"
              )}
            </Button>
          </Stack>
          <Typography
            variant="body2"
            color="text.secondary"
            mt={3}
            textAlign="center"
          >
            {mode === "login"
              ? "Ainda não tem uma conta? "
              : "Já possui uma conta? "}
            <Link
              component="button"
              type="button"
              onClick={() => setMode(mode === "login" ? "register" : "login")}
            >
              {mode === "login" ? "Cadastre-se" : "Entrar"}
            </Link>
          </Typography>
        </Paper>
      </Container>
    </Box>
  );
}
