# Kernel quality gates

`mutation_runner.py` applies an explicit manifest to a copied fixture. Supported operations are
identifier rename, API substitution, unique text wrapping, and file/directory rearrangement. The
runner refuses in-place output, traversal, existing destinations, unknown operations, and no-op
changes. The original fixture and its expected outcome remain immutable, so the same evaluator can
compare the base case with every generated variant.

`mutation-suite.json` defines five independent variants: identifier rename, method wrapping, API
replacement, directory rearrangement, and properties-to-YAML configuration replacement. Build all
variants with `python benchmarks/kernel_quality/mutation_runner.py <source> <output>
benchmarks/kernel_quality/mutation-suite.json --suite`.

`anti_overfit.py` scans production runtime files for benchmark-only names listed in
`forbidden-identifiers.txt`. Run it before tests:

```powershell
python benchmarks/kernel_quality/anti_overfit.py
pytest -q
```

Blind evaluation inputs must contain only source, scope, and user-supplied security context. The
oracle is supplied to the evaluator through a separate path after the audit result is frozen. Do
not place expected findings, standard item IDs, or oracle reasons in model input manifests.
`blind/` contains three opaque Java/Spring cases and SHA-256 commitments, but no plaintext oracle.
`blind_evaluator.py` rejects an oracle inside that directory and verifies every external answer
against its commitment before scoring a complete frozen result set.
