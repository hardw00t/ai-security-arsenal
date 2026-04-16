# ESLint Security Reference (JavaScript / TypeScript)

ESLint is a linter; the security plugins add rule sets. Best for fast, in-editor feedback and PR gating. Lower depth than Semgrep/CodeQL on dataflow.

## Install

```bash
npm install --save-dev \
  eslint \
  eslint-plugin-security \
  eslint-plugin-no-unsanitized \
  eslint-plugin-security-node       # optional: Node.js extras
```

For TypeScript:
```bash
npm install --save-dev \
  @typescript-eslint/parser \
  @typescript-eslint/eslint-plugin
```

## Config (`.eslintrc.json` — classic) 

```json
{
  "parser": "@typescript-eslint/parser",
  "plugins": ["security", "no-unsanitized", "@typescript-eslint"],
  "extends": [
    "plugin:security/recommended-legacy",
    "plugin:@typescript-eslint/recommended"
  ],
  "rules": {
    "security/detect-object-injection": "error",
    "security/detect-non-literal-require": "error",
    "security/detect-non-literal-fs-filename": "error",
    "security/detect-eval-with-expression": "error",
    "security/detect-child-process": "error",
    "security/detect-buffer-noassert": "error",
    "security/detect-pseudoRandomBytes": "error",
    "security/detect-unsafe-regex": "error",
    "no-unsanitized/method": "error",
    "no-unsanitized/property": "error"
  }
}
```

## Flat config (ESLint >= 9, `eslint.config.js`)

```js
import security from "eslint-plugin-security";
import noUnsanitized from "eslint-plugin-no-unsanitized";
export default [
  security.configs.recommended,
  { plugins: { "no-unsanitized": noUnsanitized },
    rules: {
      "no-unsanitized/method": "error",
      "no-unsanitized/property": "error"
    }
  }
];
```

## Invocation

```bash
npx eslint --ext .js,.ts,.jsx,.tsx src/

# SARIF output via formatter
npm install --save-dev @microsoft/eslint-formatter-sarif
npx eslint --format @microsoft/eslint-formatter-sarif \
           --output-file eslint.sarif \
           src/
```

## High-value rules

| Rule | Class |
|------|-------|
| security/detect-eval-with-expression | `eval` with dynamic content |
| security/detect-child-process | `child_process.exec` with variable |
| security/detect-non-literal-fs-filename | Path traversal via fs |
| security/detect-non-literal-regexp | ReDoS via dynamic regex |
| security/detect-non-literal-require | RCE via dynamic require |
| security/detect-object-injection | Prototype pollution / property injection |
| security/detect-pseudoRandomBytes | Weak random in crypto context |
| security/detect-unsafe-regex | Known ReDoS patterns |
| no-unsanitized/method | `el.insertAdjacentHTML` with user data |
| no-unsanitized/property | `el.innerHTML = userInput` |

## Known FP patterns

- `detect-object-injection` is the noisiest rule in the plugin — often fires on safe `obj[key]` where `key` is from a typed enum. Consider downgrading to `warn`.
- `detect-non-literal-fs-filename` fires on any `fs.readFile(variable)` — needs taint context.
- `detect-child-process` fires on static imports of `child_process` even if unused.

## Pair with

- Semgrep `p/javascript p/nodejs p/react p/express` for higher-fidelity framework patterns.
- CodeQL JavaScript suite for inter-procedural taint.
- `npm audit` / `osv-scanner` for dependency CVEs — see sca-security.

## Framework packs

- React-specific: `eslint-plugin-react`, `eslint-plugin-jsx-a11y` (accessibility, adjacent).
- Node.js extras: `eslint-plugin-security-node` (HTTP header checks, timing attacks).
