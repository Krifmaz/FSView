// Light / dark / system theme, persisted per browser (same model as Caddymium).
import { useEffect, useState } from "react";

export type ThemeChoice = "light" | "system" | "dark";
const KEY = "fsview-theme";
const mq = window.matchMedia("(prefers-color-scheme: dark)");

function read(): ThemeChoice {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch {
    /* storage unavailable */
  }
  return "system";
}

let choice: ThemeChoice = read();
const listeners = new Set<(c: ThemeChoice) => void>();

function apply() {
  const dark = choice === "dark" || (choice === "system" && mq.matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", dark ? "#0b0b0d" : "#f7f7f8");
}
mq.addEventListener("change", apply);
apply();

export function setTheme(c: ThemeChoice) {
  choice = c;
  try {
    localStorage.setItem(KEY, c);
  } catch {
    /* private mode */
  }
  apply();
  listeners.forEach((l) => l(c));
}

export function useTheme(): [ThemeChoice, (c: ThemeChoice) => void] {
  const [c, set] = useState(choice);
  useEffect(() => {
    listeners.add(set);
    return () => {
      listeners.delete(set);
    };
  }, []);
  return [c, setTheme];
}
