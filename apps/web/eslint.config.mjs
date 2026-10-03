import nextVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

export default [
  { ignores: [".next/**", "coverage/**", "next-env.d.ts"] },
  ...nextVitals,
  ...nextTypescript
];
