import { useState } from "react";
import { useNavigate } from "react-router-dom";
import AuthPage from "../components/AuthPage/AuthPage.jsx";
import { cadastrar, entrar } from "../services/index.js";

export default function LoginPage() {
  const navigate = useNavigate();
  const [error, setError] = useState("");

  const authenticate = async (form, mode) => {
    try {
      const result = mode === "login"
        ? await entrar(form.username, form.password)
        : await cadastrar(form.username, form.password);
      const username = result.username || form.username.trim().toLowerCase();
      sessionStorage.setItem("shed.username", username);
      setError("");
      navigate("/chat", { replace: true });
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  return <AuthPage onSubmit={authenticate} error={error} />;
}
