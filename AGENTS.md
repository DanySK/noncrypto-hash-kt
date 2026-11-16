# Agent Instructions

This is a Kotlin Multiplatform library of non-cryptographic hash functions.
Its priorities, in order, are: portability across targets, speed, and memory footprint.
When they conflict, follow that order.

## Building and validating

Use repository-defined Gradle tasks from the repository root. Do not replace them with ad hoc shell commands or per-tool alternatives.

Gradle needs a JDK 17 or newer to run, even though the library is compiled for JVM 8 through toolchains.
If the default JVM is older, point `JAVA_HOME` to a newer JDK for the Gradle invocation; do not change the toolchain or the JVM target.

Run `./gradlew --parallel build` as the final validation step for any non-trivial change. If that fails, keep fixing the change and rerun until it passes or you hit an external blocker.
Targets that cannot be built on the current host (e.g., Apple targets on Linux) are skipped by Gradle: say so when reporting, instead of claiming they were validated.

Format before the final validation run:
- If you changed Kotlin files, run `./gradlew --parallel ktlintFormat`.
- After formatting, rerun the relevant verification tasks and finish with `./gradlew --parallel build`.

Use narrower Gradle tasks only to iterate faster while working (e.g., `jvmTest`, `jsNodeTest`, `wasmJsNodeTest`, `linuxX64Test`, `detekt`, `ktlintCheck`).
Do not stop at `assemble`, `test`, or a single target when the change affects shared code, build logic, or release behavior.
Warnings are errors on every target.

## Design rules

Keep all code in `commonMain` unless a platform-specific implementation is measurably faster; in that case, use `expect`/`actual` and keep the results identical on every target.

Hashes must be identical on every target. In particular:
- absorb multi-byte values little-endian, and text as UTF-8;
- never rely on platform-dependent behavior, such as `toString()` of floating point numbers, `KClass.qualifiedName`, iteration order of hash-based collections, or `encodeToByteArray()` on malformed text;
- add a test for every encoding decision, and run it on at least JVM, JS, Wasm, and one native target.

Avoid allocations on hot paths: `Digest.update` overloads, one-shot `HashFunction` methods, and the structured encoding of primitives, strings, and arrays.
Prefer `const val` for constants used on hot paths, so that they are inlined.

The structured encoding of `updateValue` is part of the stability contract: changing it changes every structured hash.
Never renumber the tags in `ValueTag`; append new ones at the end.

## Code style

Preserve the existing structure. Keep changes small, local, and consistent with the style already used in the touched files. Avoid mixing unrelated refactors into a focused fix.

Order the members of Kotlin classes, interfaces, and objects as follows, extending the class layout of the Kotlin coding conventions:
1. Properties and `init` blocks, other than extension properties: first `const` properties, then the other plain properties, without a custom getter or setter (private state included), then properties with custom accessors.
2. Secondary constructors.
3. Functions, including overrides, other than extension functions: first the non-private ones, then the private helpers.
4. Member extensions: extension properties before extension functions, and in each, non-private ones before private helpers.
5. Nested types used inside the class.
6. The companion object, whose members follow these same rules.
7. Nested types meant for use outside the class and not referenced inside it.
Within each group, keep members adjacent when they clearly work together, such as the members implementing the same supertype, or hooks next to the function that calls them.
Otherwise, sort them alphabetically by name, which also keeps overloads adjacent.
Apart from private helpers going last, do not sort by visibility, and do not reorder members only to satisfy visibility or alphabetical order.
Apply the same rules to top-level declarations within a file.

Initialization order overrides every other ordering rule: fields, properties, and initializer blocks run in declaration order, so a member that reads another one during initialization must stay after it.
Reorder members only in the classes a change already touches, in a separate `style` commit unless asked otherwise.

Do not suppress warnings unless there is no real fix. Every suppression must be narrowly scoped and explained with a short justification next to the suppression site.

Document every public declaration with KDoc. Internal and private declarations need KDoc only when their purpose is not obvious.

## Tests

Put tests in `commonTest`, so that they run on every target.
Name test functions with readable sentences in backticks, such as `` `all NaNs hash the same` ``.
Avoid characters that some targets reject in function names: `.`, `:`, `/`, `\`, `<`, `>`, `[`, `]`.

Validate every hash algorithm against the reference test vectors of its specification, for both the streaming `Digest` and the one-shot `HashFunction` methods, including inputs that cross block boundaries.

## Commits

Treat generated files, caches, and build outputs as non-source artifacts. Do not commit them unless the task explicitly requires it.

Use Conventional Commits for any commit you create. Use the header format `type(scope): summary`; for breaking changes use `type(scope)!: summary` and add a `BREAKING CHANGE:` footer.

Prefer release-aware commit types:
- Use `feat` for user-visible features.
- Use `fix` for bug fixes.
- Use `docs`, `perf`, or `revert` when they match the actual change.
- Use `chore(api-deps)` for dependency updates expected to trigger a minor release.
- Use `chore(core-deps)` for dependency updates expected to trigger a patch release.
- Use `test`, `ci`, `build`, `style`, `refactor`, and other `chore(...)` scopes for non-release maintenance work.
- Use `chore(...)` or `ci(...)`, not `docs(...)`, for changes to agent instructions, skills, or automation policy.

Changing the output of a hash function or of the structured encoding is a breaking change.
