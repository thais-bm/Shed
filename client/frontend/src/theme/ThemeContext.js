import { createContext, useContext } from "react";

export const ThemeModeContext = createContext(null);

export function useAppTheme() {
  const context = useContext(ThemeModeContext);
  if (!context) throw new Error("useAppTheme deve ser usado dentro de AppThemeProvider.");
  return context;
}
