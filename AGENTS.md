# AGENTS.md

Guidance for AI agents (opencode, Claude Code, etc.) working in this repository.

## Project

Minima Core — a decentralized blockchain node implementation in Java. Source lives under `src/`, tests under `test/`. Build is Gradle 8.12.1 targeting Java 11.

## Build & Test

```bash
# Compile main sources
./gradlew compileJava

# Full clean build (compiles + tests + shadow jar)
./gradlew clean build

# Run the test suite (290 tests, must be 0 failures)
./gradlew test

# Build the fat jar (build/libs/minima-*.jar)
./gradlew shadowJar

# Helper script (wraps the build + jar copy)
./buildjars.sh
```

There is no dedicated lint task; the `compileJava`/`compileTestJava` tasks surface warnings. Re-run `./gradlew test` after any non-trivial change and confirm 290/290 passing before committing.

## Conventions

- **Package layout**: `org.minima.<subsystem>.*` — keep new code under the appropriate subsystem (e.g. `org.minima.system.commands.*` for CLI commands).
- **Naming**: classes are PascalCase; methods/fields are camelCase. Command classes are lowercase (e.g. `decryptbackup.java`) — follow existing command files when adding one.
- **No comments unless necessary**: do not add explanatory comments. Do not leave `// TODO Auto-generated` stubs; either implement or remove.
- **No TODO/FIXME/HACK markers**: track work in issues, not source comments. `grep -rn "TODO\|FIXME\|HACK\|XXX" src/` must return nothing.
- **Error handling**: never swallow exceptions silently. Log via `MinimaLogger.log(...)` and rethrow or wrap in the domain exception (`CommandException`, `ExecutionException`, etc.).
- **Security**: see SECURITY.md §7.1 and §11.2 for the mandatory review checklist. In particular: validate file paths (`MiniFile.createBaseFile` + `validateFileAccess`), validate network targets (`validateAndResolveURI`/`validateAndResolveHost`), use parameterized SQL, and require RSA-OAEP-4096 + AES-256-GCM + fresh 12-byte IVs.
- **Proof system**: WOTS+ keys must throw on exhaustion (never reset), monotonic cache fields must be reset together, `convertMiniDataVersion()` must not return null, proof chain length must be bounded, all stream deserialization must use try-finally. See SECURITY.md §13 for full details.
- **Tests**: JUnit 4 (`junit:junit:4.13.2`). Security validation tests live in `test/org/minima/utils/security/SecurityValidationTests.java`. Add a regression test for any security-relevant fix.
- **Shadow plugin**: `com.gradleup.shadow:8.3.11` (new plugin ID, migrated from `com.github.johnrengelman.shadow`).

## Commit & Push

- Commit messages are concise, imperative, lowercase-first-word-optional style consistent with recent history (e.g. `Clean up TODO/HACK markers: ...`).
- Do not commit the pre-existing `README.md` / `SECURITY.md` / `WHITEPAPER.md` doc edits unless they are part of the requested change.
- `main` tracks `origin/main`. Push with `git push` after committing.

## Validation Before Commit

1. `./gradlew compileJava` succeeds (no errors; pre-existing deprecation/unchecked warnings are acceptable)
2. `./gradlew test` reports 290 tests, 0 failures, 0 errors
3. `grep -rn "TODO\|FIXME\|HACK\|XXX" src/` returns no matches

## Releasing

Releases are automated via `.github/workflows/release.yml`. To cut a release, push a `v*` tag:

```bash
git tag vX.Y.Z.W
git push origin vX.Y.Z.W
```

The workflow builds the fat jar (`./gradlew clean shadowJar`), runs the full test suite, and publishes a GitHub Release with the jar attached. CI (`.github/workflows/ci.yml`) runs compile + tests + the marker scan on every push and pull request to `main`.