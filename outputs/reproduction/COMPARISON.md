# Fresh-clone reproduction comparison

Reproduced from a fresh copy of the pack repository alone: the harness
was re-run in a temporary directory with no access to the original
outputs, no clone of any other repository, no Conan, and no package
manager. Pinned-source evidence is vendored in evidence/.

- Python: Python 3.12.3
- System: Linux 7.0.0-44-generic x86_64
- Fresh copy: temporary directory (removed after the run)
- Digest verification in fresh copy: PASS

| Output file | Committed SHA-256 | Reproduced SHA-256 | Result |
|---|---|---|---|
| coverage.json | 6ef6e638f90ba5571f8b3b7d8cccf154b534212b93186826cc820a813536faaa | 6ef6e638f90ba5571f8b3b7d8cccf154b534212b93186826cc820a813536faaa | MATCH |
| inventory_check.json | 09bf36c617ae555d3fcd372c40cfd819d51be34b64f4a23c5cb0acb2f28b689f | 09bf36c617ae555d3fcd372c40cfd819d51be34b64f4a23c5cb0acb2f28b689f | MATCH |
| manifest_model.json | 4f86779ef36f8398994836ec6915fbd4ebbd662d7fc5d359a00bf79dc4c5be6b | 4f86779ef36f8398994836ec6915fbd4ebbd662d7fc5d359a00bf79dc4c5be6b | MATCH |
| pcr_model.json | 36df1e30b091df658aab0cf5a9abd08db4aa69a65fd96a5645d83a8eca26e375 | 36df1e30b091df658aab0cf5a9abd08db4aa69a65fd96a5645d83a8eca26e375 | MATCH |
| quote_verify.json | ced37bb2d3c522f2142378acf7d11fb59c3c2e1d103444850792721154867e6d | ced37bb2d3c522f2142378acf7d11fb59c3c2e1d103444850792721154867e6d | MATCH |
| seal_model.json | 20b24fdae38cc8d1e98cae1fe99dd0ab3c42ee65bda18b927bf320df9db39153 | 20b24fdae38cc8d1e98cae1fe99dd0ab3c42ee65bda18b927bf320df9db39153 | MATCH |

Result: REPRODUCED. Every regenerated output is byte-identical to the committed output, and digest verification passes in the fresh copy.
