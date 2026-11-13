# PHISH-X — Presentation, Live Demo & Viva Guide

This guide is a speaking aid for the project presentation. It is based on the current implementation; do not claim features or experiments that are not listed here.

## 1. Suggested presentation structure

### Slide 1 — Title
**PHISH-X: Phishing X-Ray — Explainable URL Detection with Numerical Optimization**

One-line pitch: *PHISH-X does not only classify a URL; it shows how the numerical model reached its score and reports structural URL warnings separately.*

### Slide 2 — Problem and motivation
- Phishing URLs can imitate trusted services.
- A label alone is not enough for an analyst to inspect a decision.
- The project combines classification, score explanation, and structural inspection.

### Slide 3 — System workflow
Show this flow:

```text
URL input → Feature extraction → Saved scaler → Logistic Regression
                                      ↓
                         Prediction + probabilities
                                      ↓
                         Additive feature contributions

URL input → Strict structural parser → Independent rule-based advisories
```

Emphasize that the advisory layer does not change the ML prediction and that the URL is not opened or fetched.

### Slide 4 — Dataset and split
- Target: 0 = Phishing, 1 = Legitimate.
- Five numerical inputs are used by the classifier.
- Primary evaluation: Group Split by Host.
- Group Train: 81,525; Group Test: 19,337; shared hosts: 0 (current checked-in split metadata).
- Explain why a random split can leak host identity across partitions.

### Slide 5 — Numerical standardization and Logistic Regression
Present the mean/variance/standardization equations, sigmoid, and regularized Binary Cross-Entropy. Explain that the scaler is fitted on training data only and reused unchanged for test and inference.

### Slide 6 — Gradient Descent
Show the analytical gradient and batch update. Explain the learning rate and the measured loss history in the Optimization Lab.

### Slide 7 — Newton-Raphson and linear solver
Show the Hessian-based Newton system, damping, backtracking line search, and Gaussian Elimination with Partial Pivoting. State clearly that the core model is not fitted with a built-in scikit-learn Logistic Regression estimator or optimizer.

### Slide 8 — Explainability and structural assessment
- Contributions add to the model logit.
- Positive contribution → toward Legitimate; negative → toward Phishing.
- Contributions are not causal explanations and are not probabilities.
- Structural advisories are a separate, rule-based channel.

### Slide 9 — Results and limitations
- Accuracy: 98.08%.
- Phishing precision: 98.91%.
- Phishing recall: 97.90%.
- Phishing F1: 98.41%.
- Test size: 19,337.
- Show the confusion matrix and discuss the 246 phishing false negatives.
- Mention dataset shortcuts/bias and that the score is not a guarantee for future campaigns.

### Slide 10 — Conclusion and future work
- Demonstrated numerical optimization from equations to a working classifier.
- Compared Gradient Descent and Newton-Raphson.
- Added score explanations and independent URL-structure advisories.
- Future work: reconcile historical dataset-count snapshots, evaluate on a newer external dataset, add carefully sourced reputation/context data, and validate drift.

## 2. Suggested 4–5 minute live demo

1. Open the Streamlit workbench with `streamlit run app/main.py`.
2. Open **URL Investigation**.
3. Submit a benign-looking placeholder such as `https://example.com/login`. Explain that `example.com` is a reserved example domain; this demonstrates the pipeline only and is not a live-site verdict.
4. Point out the predicted class, both probabilities, threshold, and the five model inputs.
5. Explain the contribution signs: positive moves toward Legitimate, negative moves toward Phishing. Do not describe a feature contribution as causal.
6. Show the independent structural assessment using a URL containing misleading user-info, for example `http://paypal.com@evil.test/login`. Explain that the actual destination host is the part after `@`; this is a parser/advisory demonstration, not a claim that the URL was visited.
7. Open **Optimization Lab** and run the comparison. Point to the measured loss, iteration count, runtime, and convergence history for each method.
8. Open **Model Evaluation**. Show both class-specific metric groups and the confusion matrix. Stress that phishing recall is important.
9. End with the limitations: host-separated dataset evaluation, lexical features, no external reputation lookups, and no guarantee of safety.

If the local model artifact is missing, run `python src/phishx/models/train.py` first. Do not spend presentation time debugging a fresh environment; generate and verify the artifact before the demo.

## 3. New analysis labs

### Threat Simulation Lab
- Enter a baseline HTTP/HTTPS URL and run controlled, synthetic variations: scheme change, added subdomain label, appended account path, and query marker.
- Compare the saved model's phishing/legitimate scores and five model-feature values for each variant.
- All processing is local. The tool does not open URLs or perform network requests.
- Describe this as a small controlled sensitivity experiment, not a complete adversarial-robustness benchmark and not proof that a changed URL is malicious.

### Confidence & Uncertainty Lab
- Inspect both class probabilities, the top-class score, distance from a selected decision threshold, and binary entropy.
- Move the threshold slider to explore how the displayed class decision changes. This does not retrain or modify the saved model.
- Call these score-based uncertainty indicators or a confidence proxy. Do not call them calibrated confidence or claim they estimate real-world certainty; no calibration procedure is currently implemented.

## 4. Viva questions and concise answers

**Q1. Why did you choose Logistic Regression?**  
It is suitable for binary classification, produces probabilities through the sigmoid function, and has a transparent objective, gradient, and Hessian that make it appropriate for demonstrating numerical optimization.

**Q2. What is the role of the sigmoid function?**  
It maps the linear score (z=w^Tx+b) to a value between 0 and 1, interpreted by the model as the probability of the positive class, Legitimate (label 1).

**Q3. Why use Binary Cross-Entropy?**  
It is the standard likelihood-based loss for binary probabilistic classification. It penalizes confident incorrect predictions and is differentiable for optimization.

**Q4. Why add L2 regularization?**  
It penalizes large feature weights, helping control model complexity. In this implementation the bias is not regularized.

**Q5. What is the difference between Gradient Descent and Newton-Raphson?**  
Gradient Descent uses the first derivative and a chosen learning rate. Newton-Raphson also uses curvature information from the Hessian to calculate a direction, often converging in fewer iterations near the optimum at the cost of solving a linear system.

**Q6. Why is Newton-Raphson not simply one formula in code?**  
The Hessian system may be ill-conditioned. The implementation uses damping, a pivoted linear solver, backtracking line search, and stopping checks to make the numerical update more stable.

**Q7. What is Gaussian Elimination with Partial Pivoting?**  
It solves a linear system by selecting a large-magnitude pivot, swapping rows, eliminating entries below the pivot, and using back substitution. Partial pivoting reduces numerical problems caused by small pivots.

**Q8. Why not use `numpy.linalg.solve` or `sklearn.LogisticRegression`?**  
The course objective is to demonstrate the numerical method itself. The project therefore implements the Newton linear solve and Logistic Regression optimization directly. NumPy is still used for array representation and vectorized arithmetic.

**Q9. Why standardize features?**  
The five URL features have different numerical scales. Standardization gives them comparable scales and generally improves numerical conditioning for gradient-based optimization.

**Q10. Why fit the scaler only on the training set?**  
Using test-set statistics would leak information from evaluation data. The scaler is fitted on Group Train and reused unchanged on Group Test and inference.

**Q11. Why Group Split by Host instead of only a random split?**  
A random split can put URLs from the same host in both partitions. Group splitting keeps each host in one partition and provides a more meaningful test of performance on unseen hosts.

**Q12. What does 98.08% accuracy mean?**  
It is the fraction of correctly classified URLs in the fixed 19,337-sample Group Test set. It is not a guarantee for future URLs or new phishing campaigns.

**Q13. Why report phishing recall separately?**  
Phishing recall measures the fraction of actual phishing samples correctly detected. It directly reflects missed phishing cases, which are important in a security application.

**Q14. What does a feature contribution mean?**  
It is the feature's additive contribution to the model logit after standardization. Positive values move the score toward Legitimate; negative values move it toward Phishing. It is not a causal explanation or a probability.

**Q15. Why is the structural security assessment separate from the ML model?**  
It keeps deterministic parser findings transparent and prevents a heuristic rule from silently changing a learned probability. The analyst can inspect both outputs independently.

**Q16. Does HTTPS mean a URL is safe?**  
No. HTTPS protects transport to a domain; phishing sites can also use HTTPS. It is not proof of legitimacy.

**Q17. Does a direct IP address always mean phishing?**  
No. It can be legitimate, especially in private networks. PHISH-X reports it as a low-severity advisory, not proof of maliciousness.

**Q18. What are the main limitations?**  
The dataset has collection biases and lexical shortcuts; only five lexical features feed the model; there is no live reputation, DNS, WHOIS, page-content, or browser analysis; and the evaluation is one fixed group-separated test split.

## 5. Claims to avoid during the presentation

- Do not say the system guarantees that a URL is safe.
- Do not call the 98.08% result a real-world or future-campaign accuracy guarantee.
- Do not say every extracted legacy feature is used by the classifier; the model uses exactly five.
- Do not say the structural warning changes the ML probability.
- Do not call feature contributions causal explanations.
- Do not say k-fold cross-validation was performed; the reported result is from one fixed Group Split by Host.
- Do not say URLs are visited or checked against live threat intelligence; all current analysis is local.
- Do not present reserved example domains as live websites.

## 6. Submission checklist

- [ ] Confirm the latest `main` commit is pulled locally.
- [ ] Confirm the approved dataset and split manifests exist.
- [ ] Run `python -m pytest -q` and keep the terminal result.
- [ ] Run `python src/phishx/models/train.py` and confirm both artifact and metrics paths.
- [ ] Launch Streamlit and verify URL Investigation, Optimization Lab, and Model Evaluation.
- [ ] Prepare one screenshot of each main page and one training/evaluation result.
- [ ] Keep the final report and this guide available during the presentation.
