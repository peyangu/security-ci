<!-- Optional notes for the AI security audit agent, appended to its prompt.
     List this repo's untrusted-input boundaries with file paths, how tests run,
     and path aliases. Delete this file if you do not use the agent. -->

- Untrusted input boundaries:
  - (e.g.) save import/export in `src/core/save.ts`
- Tests run in Node with Vitest via `npm run test:security`.
