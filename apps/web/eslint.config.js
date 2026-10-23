import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import svelte from "eslint-plugin-svelte";
import globals from "globals";
import ts from "typescript-eslint";

export default defineConfig(
  { ignores: ["dist/", "src/wasm/"] },
  js.configs.recommended,
  ...ts.configs.strictTypeChecked,
  ...svelte.configs.recommended,
  {
    languageOptions: {
      globals: globals.browser,
      parserOptions: {
        projectService: { allowDefaultProject: ["eslint.config.js"] },
        extraFileExtensions: [".svelte"],
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ["**/*.svelte", "**/*.svelte.ts"],
    languageOptions: { parserOptions: { parser: ts.parser } },
  },
  {
    files: ["eslint.config.js"],
    extends: [ts.configs.disableTypeChecked],
  },
  {
    rules: {
      // Sink di iniezione HTML/codice vietati: la UI non deve mai interpretare markup.
      "svelte/no-at-html-tags": "error",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-restricted-properties": [
        "error",
        { property: "innerHTML", message: "Vietato: usare il templating Svelte." },
        { property: "outerHTML", message: "Vietato: usare il templating Svelte." },
        { property: "insertAdjacentHTML", message: "Vietato: usare il templating Svelte." },
        { object: "document", property: "write", message: "Vietato." },
        { object: "Math", property: "random", message: "Usare crypto.getRandomValues()." },
      ],
      "no-restricted-globals": [
        "error",
        { name: "localStorage", message: "Nessun dato in localStorage: usare il vault cifrato." },
        {
          name: "sessionStorage",
          message: "Nessun dato in sessionStorage: usare il vault cifrato.",
        },
      ],
    },
  },
);
