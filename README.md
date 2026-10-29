# Ransomware Behavior Lab

A defensive, explainable ransomware detector built around three hand-written data structures: a
**binary decision tree** (CART, grown from the data), an **n-ary process tree** (the parent/child
chain of a compromised machine) and a **binary max-heap** (the analyst triage queue). The frontend
is a Streamlit application that switches between English and Spanish at runtime.

> This project detects behavior; it does not produce it. It contains no malware and no evasion
> payloads. Training data is **synthetic by default**: the numbers below demonstrate the method, not
> field accuracy. Section [Using real telemetry](#using-real-telemetry) explains what it takes to
> make a claim about real detection.

```bash
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
python -m pytest                # 58 tests
```

## What the lab does

1. **Grows a decision tree** from labeled behavior observations (5 numeric features per process).
2. **Classifies a process and explains itself**: every verdict carries the exact rules that were
   evaluated, the observed reading for each one, and the training support of the leaf it landed on.
3. **Reconstructs the attack chain**: a detected process marks its ancestors as suspects, because
   the parent that launched a locker is part of the incident.
4. **Ranks the incident**: detected processes are pushed into a max-heap so the analyst always sees
   the highest-risk process first.
5. **Shows where the model breaks**: the evasion lab lets you slow a locker down, lower its entropy
   or stop deleting shadow copies, and watch the verdict flip to benign. A false negative is an
   encrypted machine, so this is the most honest panel in the app.

---

# Data structures

## 1. Binary decision tree (CART) — `ransomware_lab/decision_tree.py`

### Representation

The tree is a **recursive object graph**, not an array: each node owns its subtrees, so a node is a
valid tree on its own and the structure needs no index arithmetic.

```
ClassificationNode (abstract)
├── BehaviorSplit   → rule + on_match + on_violation   (internal node, always 2 children)
└── VerdictLeaf     → class distribution               (terminal node)
```

Both node types implement the same four operations — `resolve`, `accept`, `walk`, `height` — so
every traversal is polymorphic and there is not a single `isinstance` check in the hot path. A node
stores only what it learned during training (`sample_count`, `ransomware_ratio`), never a reference
back to the training rows, which keeps a trained tree small and independent of the dataset.

`DecisionRule` is an immutable `(feature, threshold)` pair with the comparison built in
(`reading <= threshold` goes left). Keeping the comparison inside the rule is what lets the UI
print a human-readable reason without re-deriving the direction of the test.

### How it is built

`CartTreeBuilder._grow` is the classic recursive CART procedure:

1. Stop and emit a `VerdictLeaf` if the node is pure, too deep or too small (`GrowthLimits`).
2. Otherwise find the split that maximizes the impurity decrease
   `ΔI = I(parent) − (n_left/n)·I(left) − (n_right/n)·I(right)`.
3. Partition the observations once with the winning rule and recurse on both halves.

The split search is the part worth reading. The naive version tests every candidate threshold by
re-partitioning the dataset, which costs `O(m · n²)` per node and makes the UI unusable. Instead,
`_sweep` sorts the observations **once per feature** and walks them in order, maintaining running
counts of the left side:

```
sorted by feature →  o₁  o₂  o₃  o₄  o₅  o₆ ...
                         ↑ candidate threshold = midpoint(o₂, o₃)
left  = (size, malicious)   updated in O(1) per step
right = (total − size, malicious_total − malicious)
```

Because Gini and entropy depend only on `(size, malicious)`, each candidate is scored in `O(1)` and
the whole node costs `O(m · n log n)`, dominated by the sort. Thresholds are placed at the midpoint
between consecutive distinct values, and candidates that would leave a leaf below
`min_samples_leaf` or gain less than `min_impurity_decrease` are discarded during the sweep.

| Operation | Cost | Where |
|---|---|---|
| Train | `O(m · n log n)` per node | `CartTreeBuilder._grow` |
| Classify one process | `O(h)`, h = height | `BehaviorSplit.resolve` |
| Trace the explanation | `O(h)` | `BehaviorDecisionTree.trace` |
| Height / leaf count / walk | `O(k)`, k = nodes | `ClassificationNode.walk` |
| Feature importance | `O(k)` | `_ImpurityImportance` (Visitor) |

With the default profiles the tree comes out at **height 5, 9 leaves, 17 nodes** over 650
observations — small enough to read on screen, which is the entire point of choosing a tree over an
ensemble here.

### Explainability

`trace` returns a `DecisionPath` holding the ordered `RuleOutcome`s, the leaf that was reached and
the node objects that were visited. The UI uses the outcomes for the reason list and the visited
nodes to highlight the path inside the rendered diagram. The path carries **structured data, not
preformatted sentences**, which is what makes the explanation translatable.

The impurity criterion is a Strategy (`GiniImpurity`, `ShannonEntropyImpurity`) exposing
`score(total, malicious)`. That signature — counts instead of a dataset — is what allowed the
sweep optimization without special-casing either criterion.

## 2. N-ary process tree — `ransomware_lab/process_tree.py`

### Representation

A `MonitoredProcess` is a Composite node holding a parent pointer and an ordered list of children,
so the structure is an arbitrary-arity tree that mirrors how an operating system reports lineage:

```
System (4)
├── winword.exe (1004)
│   └── updater.exe (1006)        ← detected: stealth locker
└── backup-agent.exe (1005)
```

`ProcessTree` wraps the root and adds a **hash index** (`dict[int, MonitoredProcess]`) so the UI can
resolve a pid in `O(1)` instead of searching the tree on every rerun. Index and structure are
updated in the same method, which is why `attach` is the only public way to add a process.

### Traversals

Three traversals, each written for the question it answers:

- `breadth_first` — level by level, with a `collections.deque` as the FIFO queue; `popleft` is
  `O(1)`, where a list would pay `O(n)` per shift. This is the default iteration order of the tree
  because it is also the order the UI lists processes in.
- `depth_first` — iterative with an explicit stack (children pushed reversed to preserve left-to-
  right order). Iterative rather than recursive so a deep lineage cannot blow the Python stack.
- `ancestors` — walks parent pointers upward in `O(d)`; this is what turns one detection into the
  suspect chain shown in the diagram.

### Invariants

A tree that silently accepts a cycle stops being a tree, so the mutators validate first and raise
`ProcessLineageError`: duplicate pid, unknown parent, reparenting a process that already has one,
and attaching an ancestor beneath its own descendant (the cycle case, checked against the ancestor
walk). Each rule has a test in `tests/test_process_tree.py`.

| Operation | Cost |
|---|---|
| `attach` / `find` / `require` | `O(1)` amortized (+ `O(d)` cycle check on attach) |
| `breadth_first` / `depth_first` | `O(n)` |
| `ancestors` / `lineage_of` | `O(d)` |
| `height` | `O(n)` |

## 3. Binary max-heap priority queue — `ransomware_lab/triage.py`

### Representation

`ThreatTriageQueue` is a **complete binary tree flattened into a Python list** — written out with
explicit index arithmetic rather than delegating to `heapq`, because the heap is the subject here:

```
index:    0      1      2      3      4      5
        0.98   0.91   0.74   0.55   0.60   0.41
parent(i) = (i−1)//2      children(i) = 2i+1, 2i+2
```

The heap property is `parent.priority >= child.priority` for every node, so `_tickets[0]` is always
the highest-risk alert. `_sift_up` restores it after an append and `_sift_down` after the root is
replaced by the last element — the standard pair of `O(log n)` repairs.

### Ordering

A heap is only as good as its comparison. `TriageTicket.priority` returns `(risk, -arrival)`:
risk decides, and on a tie the ticket that arrived first wins, so equal-risk alerts keep FIFO order
instead of whatever order the array happens to be in. `arrival` is excluded from equality
(`compare=False` on the field) so two tickets describing the same alert still compare equal.

`holds_heap_invariant()` checks the property across the whole array; the test suite calls it after
every push and pop of 400 randomized tickets, which is how the sift logic is verified rather than
assumed.

| Operation | Cost |
|---|---|
| `admit` (push) | `O(log n)` |
| `pop` | `O(log n)` |
| `peek` | `O(1)` |
| `most_critical(k)` | `O(n + k log n)`, non-destructive (works on a copy) |
| `drain` | `O(n log n)`, yields risk in non-increasing order |

## 4. Supporting structures

| Structure | Where | Why it is the right one |
|---|---|---|
| Immutable tuple vector | `BehaviorVector` | Fixed-width feature vector with `O(1)` access by feature; `with_reading` returns a new vector, so an observation can never be mutated behind the detector's back |
| Read-only sequence | `TelemetryDataset` | Wraps a tuple of observations and answers `class_counts`, `malicious_count`, `is_pure`, `subset` without copying rows per query |
| Hash index | `ProcessTree._by_pid` | `O(1)` pid lookup for a UI that resolves pids on every rerun |
| FIFO deque | `MonitoredProcess.breadth_first` | `O(1)` dequeue for level-order traversal |
| Stratified fold buckets | `StratifiedFoldSplitter` | Round-robin assignment of per-class index lists, so every fold keeps the original class ratio |

---

# Object-oriented design

| Concept | Where | What it buys |
|---|---|---|
| Inheritance + polymorphism | `ClassificationNode` → `BehaviorSplit`, `VerdictLeaf` | Traversal and classification without type checks |
| Composite | `MonitoredProcess` | A process and a subtree expose the same interface |
| Strategy | `ImpurityCriterion`, `BehaviorProfile`, `FeatureDistribution`, `TelemetrySource` | Gini vs entropy, synthetic vs CSV, Gaussian vs Bernoulli — all swappable without touching callers |
| Visitor | `TreeVisitor` → `_ImpurityImportance`, `_DotTreeRenderer` | New tree analyses and renderings without reopening the node classes |
| Facade | `RansomwareDetector` | Domain vocabulary (`assess`, `evaluate`, `feature_importance`) over a generic tree |
| Factory method | `RansomwareDetector.trained_on`, `CsvTelemetrySource.from_bytes`, `LabSession.bootstrap` | Each object has one obvious, validated way to be created |
| Value objects | `DecisionRule`, `RuleOutcome`, `ConfusionMatrix`, `TriageTicket`, `GrowthLimits` | `@dataclass(frozen=True, slots=True)`: no accidental mutation, cheap to pass around |
| Encapsulation | `_`-prefixed state + read-only properties | The detector, the tree and the heap cannot be corrupted from outside |
| Single responsibility | `diagrams.py` only emits DOT, `app.py` only renders, `session.py` only holds state | The UI contains no detection logic and the domain contains no strings |
| Fail fast | `TelemetryFormatError`, `ProcessLineageError`, threshold range check | Bad input is rejected at the boundary with the line and column that caused it |

```
trees/
├── app.py                        Streamlit UI: renders the session, forwards widget changes
├── ransomware_lab/
│   ├── telemetry.py              BehaviorFeature, BehaviorVector, TelemetryDataset
│   ├── profiles.py               behavior profiles and per-feature distributions
│   ├── sources.py                SyntheticTelemetrySource, CsvTelemetrySource
│   ├── decision_tree.py          CART: nodes, criteria, builder, explanation path
│   ├── process_tree.py           MonitoredProcess, ProcessTree
│   ├── triage.py                 ThreatTriageQueue (binary max-heap)
│   ├── evaluation.py             ConfusionMatrix, StratifiedFoldSplitter, reports
│   ├── detector.py               RansomwareDetector facade, ThreatAssessment
│   ├── session.py                LabSession application state
│   ├── diagrams.py               Graphviz DOT for both trees
│   └── i18n.py                   Translator, English/Spanish phrase tables
└── tests/                        58 tests, including headless Streamlit runs
```

# Internationalization

`Translator` is an immutable object built from a language code; `translate("key", **placeholders)`
resolves against the chosen table and falls back to English, then to the key itself, so a missing
phrase degrades instead of crashing. Both diagrams receive a `DiagramLabels` bundle, which is why
the rendered trees are translated too and `diagrams.py` never imports `i18n`. A test asserts that
every language defines exactly the same key set — the cheapest way to keep a second language from
rotting.

The domain layer never produces prose. A verdict explanation travels as `RuleOutcome` values and is
formatted by the UI, so the same detection renders as `Rename ratio = 0.91 > 0.42` in English and
`Proporción de renombrados = 0.91 > 0.42` in Spanish.

# Data

## Features

| Column | Meaning | Range |
|---|---|---|
| `files_per_sec` | Files written per second | 0–400 |
| `entropy` | Shannon entropy of written payloads, in bits per byte | 0–8 |
| `rename_ratio` | Share of writes followed by a rename | 0–1 |
| `shadow_delete` | Shadow copy / backup deletion observed | 0 or 1 |
| `dirs_touched` | Distinct directories written to | 0–400 |

## Synthetic profiles

Five profiles, three benign and two malicious. The two benign outliers are deliberate: a **backup
agent** writes fast across many directories, and an **archive compressor** produces high-entropy
output and renames the files it replaces. They exist so that no single feature separates the classes
and the tree is forced to combine them — without them the tree collapses to a trivial depth-2 rule
that would look perfect and teach nothing.

## Your own CSV

One row per process (or per process and time window):

```csv
files_per_sec,entropy,rename_ratio,shadow_delete,dirs_touched,label
80.5,7.9,0.91,1,92,1
0.7,5.1,0.00,0,3,0
```

`label` is 0 for benign and 1 for ransomware, and both classes must be present. Missing columns,
empty cells, non-numeric values and labels other than 0/1 are reported with the offending line.

# Measured results

Default synthetic dataset (650 observations, 380 benign / 270 ransomware), Gini, max depth 5, risk
threshold 0.5, stratified 5-fold cross-validation:

| Metric | Value |
|---|---|
| Recall (mean over folds) | 98.1% |
| Precision | 97.1% |
| Accuracy | 98.0% |
| Worst fold recall | 96.3% |

Feature importance: `rename_ratio` 58.9%, `dirs_touched` 20.2%, `files_per_sec` 16.1%,
`entropy` 4.9%, `shadow_delete` 0%. The last one is informative: shadow copy deletion is a strong
signal on its own, but the features above it already separate those samples, so the tree never
needs to ask.

These numbers describe the synthetic generator, not the real world. Random cross-validation is also
optimistic for this problem — see below.

# Using real telemetry

**Level 1 — public datasets.** RanSAP and its successor RanSMAP (storage and memory access patterns
captured under a hypervisor), ISOT (sandbox analysis) and CLEAR (labeled storage commands) contain
real ransomware executions. None of them ships these five features: an adapter has to aggregate
their events per process and time window and export the CSV schema above. That adapter is not
included in this repository.

**Level 2 — your own lab.** Isolated VMs with no network and restorable snapshots, Sysmon (events 1,
11, 23), ETW or auditd for collection. Malicious behavior belongs only in that lab.

**Level 3 — honest evaluation.** Split by ransomware **family** and by **time**, not at random, to
measure generalization to unseen attacks; report precision/recall/PR-AUC rather than accuracy on
an imbalanced problem; prioritize recall, since a false negative is an encrypted machine.

# Testing

```bash
python -m pytest
```

58 tests, grouped by what they protect:

- `test_decision_tree.py` — impurity edge cases, threshold placement and inclusivity, growth limits,
  path/leaf consistency, pure and empty datasets.
- `test_process_tree.py` — traversal orders, lineage, depth and height, and every rejected mutation.
- `test_triage.py` — ordering, FIFO tie-breaking, and the heap invariant checked after every push
  and pop over 400 randomized tickets.
- `test_pipeline.py` — CSV validation messages, cross-validation, the monotonic threshold/recall
  relationship, feature importance as a distribution, session behavior and translation parity.
- `test_app.py` — headless `AppTest` runs: initial render, language switch, spawning a process,
  moving the risk threshold.

# Limitations

- The process tree is simulated even when the model is trained on a real CSV; only the detector
  learns from real data.
- A single tree is interpretable but weak against evasion. The evasion lab demonstrates exactly
  that, and the next step is a forest over sliding time windows, keeping importances for
  explainability.
- Random cross-validation overstates generalization; split by family and time before claiming a
  detection rate.
