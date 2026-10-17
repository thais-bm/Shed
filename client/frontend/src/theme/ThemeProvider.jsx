import { useEffect, useMemo, useState } from "react";
import { CssBaseline, ThemeProvider as MuiThemeProvider, createTheme } from "@mui/material";
import { ThemeModeContext } from "./ThemeContext.js";

const lightPalette = {
  primary: { main: "#5b5ce2", dark: "#4849b5", contrastText: "#ffffff" },
  background: { default: "#f7f9fc", paper: "#ffffff" },
  divider: "#e6eaf0",
};

const darkPalette = {
  mode: "dark",
  primary: { main: "#a855f7", dark: "#7e22ce", light: "#c084fc", contrastText: "#ffffff" },
  background: { default: "#17151c", paper: "#211b29" },
  divider: "#3b3047",
};

export function AppThemeProvider({ children }) {
  const [mode, setMode] = useState(() => {
    const savedMode = localStorage.getItem("shed.theme");
    return savedMode === "dark" || savedMode === "light" ? savedMode : "light";
  });

  useEffect(() => {
    document.body.dataset.theme = mode;
  }, [mode]);

  const theme = useMemo(
    () => createTheme({
      palette: mode === "dark" ? darkPalette : lightPalette,
      shape: { borderRadius: 10 },
      typography: { fontFamily: '"Inter", system-ui, sans-serif' },
      components: {
        MuiButton: { defaultProps: { disableElevation: true } },
        MuiPaper: { styleOverrides: { root: { backgroundImage: "none" } } },
      },
    }),
    [mode],
  );

  const value = useMemo(() => ({
    mode,
    toggleMode: () => {
      const nextMode = mode === "dark" ? "light" : "dark";
      setMode(nextMode);
      localStorage.setItem("shed.theme", nextMode);
    },
  }), [mode]);

  return (
    <ThemeModeContext.Provider value={value}>
      <MuiThemeProvider theme={theme}>
        <CssBaseline />
        {children}
      </MuiThemeProvider>
    </ThemeModeContext.Provider>
  );
}
