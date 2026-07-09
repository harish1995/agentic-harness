import path from 'path'
import { defineConfig, devices } from '@playwright/test'

/**
 * Playwright config for the JAR Security Scanner golden-path E2E smoke test
 * (spec/roadmap.md Phase 1 gate item 7). Test files live at the repo-root
 * `tests/e2e/` (not under `frontend/`) so both frontend slices' test files
 * can coexist without either owning the other's directory tree.
 *
 * Run against the single-origin static-export + FastAPI server per
 * harness/patterns/tech-stack.md: `pnpm build` then `uv run python -m src`,
 * then `npx playwright test tests/e2e/ --reporter=line` against
 * `http://localhost:8001/app/`.
 */
export default defineConfig({
  testDir: path.resolve(__dirname, '../tests/e2e'),
  // A real end-to-end scan (decompile -> static analysis -> 7 real Anthropic
  // calls -> verify -> assemble) takes a few minutes by design
  // (spec/roadmap.md -> Key Constraints: "Correctness over speed").
  timeout: 15 * 60 * 1000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: 'line',
  use: {
    baseURL: 'http://localhost:8001',
    trace: 'retain-on-failure',
    actionTimeout: 30_000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})
