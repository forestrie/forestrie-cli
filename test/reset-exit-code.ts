/**
 * Error-path tests exercise reportError, which sets `process.exitCode = 1`.
 * Bun's test runner propagates whatever the last test left there, so without
 * a global reset the suite's exit code depends on FILE ORDERING — which
 * differs between bun versions (locally alphabetical-ish on 1.3.x, not on
 * CI's 1.2.x): 372 passing tests exited 1. Reset after every test; real
 * failures still fail the run through bun's own accounting.
 */
import { afterEach } from "bun:test";

afterEach(() => {
  process.exitCode = 0;
});
