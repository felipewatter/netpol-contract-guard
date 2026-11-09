# Contributing

We welcome reproducible bug reports, documentation improvements and narrowly scoped enhancements.

1. Open an issue explaining the operational scenario and any semantic differences from Kubernetes' documented API.
2. Reproduce with fictional namespace/Pod IP addresses and **no credentials, kubeconfig or organizational topology**.
3. Fork, branch and make focused changes. For new evaluator behavior, provide positive and negative regression tests and update `docs/FORMAT.md` and `docs/THREAT_MODEL.md` if relevant.
4. Run `python -m pip install --no-deps -e .`, `python -m unittest discover -s tests -v`, and `python scripts/build_release.py dist` locally.
5. Open a PR with risk assessment, scope limitations, and test evidence. Do not disable failing security tests to pass CI. Existing behavior should not be silently broadened.

Maintainers should not merge PRs lacking correct validation on Ubuntu/Windows/macOS, or reassign version tags that have been published. Use patch-version bumps for changes between releases and `main` when exact-head release alignment is required. See [SECURITY.md](SECURITY.md) for responsible disclosure.
