# PHISH-X — Project Proposal Summary

## Project Title

**PHISHING X-RAY — Explainable Phishing URL Detection Using Numerical Optimization**

## Project Short Name / Acronym

**PHISH-X** — Phishing X-Ray.

## Brief Project Idea

PHISH-X is a software-based security workbench that classifies URLs as Phishing or Legitimate using an explainable Logistic Regression model. Instead of relying on a built-in classifier or optimizer, the project implements the model's numerical training procedures directly from their equations. It compares Batch Gradient Descent and Newton-Raphson, then explains the resulting prediction through additive feature contributions. A separate rule-based security layer highlights suspicious URL structures without changing the model's prediction or probabilities.

## Numerical Computations Topics Used

| Course topic | How PHISH-X uses it |
|---|---|
| Numerical optimization | Minimizes the regularized Binary Cross-Entropy objective for Logistic Regression. |
| Newton-Raphson | Uses the gradient and Hessian to update model parameters. |
| Gradient Descent | Provides a first-order optimizer for comparison against Newton-Raphson. |
| Systems of linear equations | Newton's method requires solving a damped Hessian system at every iteration. |
| Gaussian Elimination with Partial Pivoting | Solves the Newton linear system using an explicit elimination and back-substitution implementation. |
| Numerical differentiation / finite differences | Used in tests to verify the analytical gradient and Hessian against finite-difference approximations. |
| Numerical standardization | Computes feature means, variances, and scaled values directly from their formulas. |

**Primary mathematical focus:** Newton-Raphson optimization and the associated system of linear equations. Gradient Descent is used as a comparison method.

## Software / Tools

- Python
- NumPy and Pandas for numerical arrays and data handling
- Streamlit for the analyst workbench
- Pytest for verification

## Expected Output

For each submitted URL, the system presents:

1. Predicted class: Phishing or Legitimate.
2. Both class probabilities and the decision threshold.
3. Five model input features.
4. Additive feature contributions and the model logit.
5. Independent structural URL advisories.
6. Model evaluation and numerical optimizer comparison views.

## Scope and Safety

The project is software-only; no hardware is required. URL analysis is local and does not visit submitted destinations or make DNS/HTTP requests. Structural findings are advisory and do not override the classifier. Evaluation uses the fixed Group Split by Host and must be interpreted with the dataset's documented limitations.

## Current Implementation Status

This proposal describes the implementation now present in the repository. For full equations, results, test evidence, and presentation notes, see:

- [Final Project Report](FINAL_PROJECT_REPORT.md)
- [Presentation, Live Demo & Viva Guide](DEMO_AND_VIVA_GUIDE.md)
- [Dataset & Evaluation Protocol](DATASET_AND_EVALUATION_PROTOCOL.md)
