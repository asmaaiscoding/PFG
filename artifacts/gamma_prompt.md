# Gamma Presentation Prompt

Copy-paste the following prompt into Gamma exactly as written:

---

Create a 10-slide professional academic presentation with a modern dark theme. Title: "PFG: Detecting Access-Control Vulnerabilities in Web Applications Using Graph Neural Networks". Use the following exact content for each slide:

**Slide 1 — Title**
Title: "Privilege Flow Graphs: Detecting Access-Control Vulnerabilities Using GNNs"
Subtitle: "PFE Project — 2025/2026"
Bottom text: "Supervised by: [Supervisor Name] | Presented by: [Your Names]"

**Slide 2 — The Problem**
Title: "Broken Access Control: #1 OWASP Top 10"
Content as bullet points:

- Access-control vulnerabilities (CWE-862, CWE-639) are the most critical web security issue
- IDOR: users access other users' data by changing an ID in the URL
- Missing Auth: sensitive endpoints exposed without login
- Existing tools (Semgrep, CodeQL) use flat pattern matching — they cannot trace data flow across multiple code layers
- They miss IDOR because they cannot reason about "does this URL parameter reach a database query without an ownership check?"

**Slide 3 — Our Solution: Privilege Flow Graphs**
Title: "Our Contribution: Privilege Flow Graphs (PFGs)"
Content: Show a diagram concept with these elements:

- We introduce a novel graph representation that captures security-relevant structure of web applications
- 4 node types: Endpoint (HTTP route), Middleware (auth guards), Service (business logic), Data Access (database queries)
- 2 edge types: "call" (function invocation) and "identifier_flow" (user-controlled parameter propagation)
- Each node stores only security-critical attributes: requires_auth, required_role, ownership_check_present, has_ownership_predicate
- The graph abstracts away irrelevant code and keeps only what matters for access-control analysis

**Slide 4 — Example: Django Code to PFG**
Title: "From Code to Graph: A Concrete Example"
Content: Show this transformation:

- Left side (Code): A Django view with @permission_classes([IsAuthenticated]) that calls services.get_order(pk), which calls Order.objects.get(pk=pk) — no user filter
- Right side (Graph): EndpointNode(requires_auth=True, ownership_check=False) → call edge → ServiceNode(get_order) → identifier_flow edge → DataAccessNode(operation=READ, has_ownership_predicate=False)
- Bottom: "The GNN sees: auth present + identifier flows to DB + no ownership check = IDOR vulnerability"
- Contrast: If the query was Order.objects.get(pk=pk, user=request.user), the DataAccessNode would have has_ownership_predicate=True → classified as SAFE

**Slide 5 — Model Architecture (PathAnalyzer)**
Title: "Model B: GATv2Conv with Target-Aware Attention Pooling"
Content as a vertical flow:

- Input: 24-dim node features + 2-dim edge features
- 3 layers of GATv2Conv (Graph Attention Network v2) with 4 attention heads
- Novel: Target-Aware Attention Pooling — scores each node relative to the specific endpoint being classified, produces endpoint-specific graph summary
- MLP classifier → 6 output classes
- Why GATv2: dynamic attention considers edge types (call vs identifier_flow), captures which connections matter most for security
- Output: SAFE, MISSING_AUTH, MISSING_ROLE, IDOR, COMBINED, INTENTIONALLY_PUBLIC

**Slide 6 — Target-Aware Pooling (Our Novel Contribution)**
Title: "Target-Aware Attention Pooling: Why It Matters"
Content:

- Problem: Standard pooling (mean/max) treats all nodes equally — but one app has both safe and vulnerable endpoints
- Our solution: Use the target endpoint's embedding as a query to compute attention over all nodes
- Formula: score_i = MLP(concat(h_i, h_target)), then softmax, then weighted sum
- Result: Same graph produces different representations depending on which endpoint we ask about
- This is critical because a single application can have 20 endpoints — some safe, some vulnerable

**Slide 7 — Training Strategy**
Title: "Mixed Training: Synthetic + Real Data"
Content:

- Synthetic data (400 samples): Generated programmatically for volume and class balance across all 6 classes
- Real data (45 samples): Extracted from 3 hand-crafted Django apps (ecommerce, social network, healthcare) with manually labeled ground truth
- Total training corpus: 445 samples
- Training result on mixed test split: 97.8% accuracy, 97.9% macro-F1
- Confusion matrix shows near-perfect separation with only 1 misclassification across all 6 classes

**Slide 8 — Evaluation Results**
Title: "Generalization: GNN vs Rule Baseline on Real Apps"
Content as a comparison table:

- Holdout experiment: trained on ecommerce+social, tested on healthcare (never seen)
- GNN Model B: Precision=0.69, Recall=0.32, F1=0.44
- Rule Baseline: Precision=0.00, Recall=0.00, F1=0.00
- Per-app: ecommerce F1=0.50 (perfect precision), social F1=0.55, healthcare F1=0.35
- Key finding: GNN achieves meaningful performance on completely unseen applications while the rule baseline fails entirely
- This proves the PFG representation captures generalizable security patterns

**Slide 9 — Why We Stand Out**
Title: "PFG vs Existing Approaches"
Content as a comparison:

- Existing tools: flat AST patterns, single-file analysis, binary output (vuln/not), manual rule writing, very weak IDOR detection
- Our approach: graph with data-flow + auth context, multi-layer analysis (view→service→DB), 6-class fine-grained classification, learns from data, strong IDOR detection via identifier_flow + ownership_predicate tracking
- Key advantage: We are the first to model the full privilege flow as a graph and apply GNNs for endpoint-level vulnerability classification

**Slide 10 — Next Steps & Conclusion**
Title: "Roadmap & Conclusion"
Content:

- Next steps: Scale to 10+ real apps (200+ endpoints), improve holdout F1 via data augmentation, add CI/CD integration (GitHub Action), add explainability (attention visualization), benchmark against Semgrep/CodeQL on same corpus
- Conclusion: We introduced Privilege Flow Graphs — a novel graph representation for web security. Our GNN-based classifier achieves 97.8% accuracy on mixed data and generalizes to unseen applications, outperforming rule-based approaches that score 0% on the same task.
- Bottom: "Tool available as CLI: pfg build → pfg train-mixed → pfg eval"

---

End of prompt. Do not add any other instructions.
