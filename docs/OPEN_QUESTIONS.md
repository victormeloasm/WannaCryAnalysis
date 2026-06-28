# Open questions and continuation plan

1. Confirm the exact short installation switch at `0x0040F538` directly from the byte listing.
2. Recover the arguments to the third `TryCreateWorkingDirectory` call inside `SelectInstallationDirectory`.
3. Label the embedded RSA key blob structure and export its public modulus/fingerprint for documentation.
4. Parse `t.wnry` independently and compare the declared plaintext size with the decrypted PE headers.
5. Reverse the decrypted `TaskStart` payload as a separate Ghidra program.
6. Reverse `u.wnry` around the `tor.exe` XREF and reconstruct its process command line and SOCKS usage.
7. Reverse `taskdl.exe` and `taskse.exe`, then connect them to the TaskStart call graph.
8. Determine whether `c.wnry`'s 4-byte and scalar fields are flags, timing values, price configuration or state.
9. Verify whether repeated launches preserve or deterministically replace the selected wallet.
10. Add a call graph and data-flow diagram after the inner components are named.
