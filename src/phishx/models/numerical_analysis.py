"""Classical Numerical Analysis baseline and syllabus demonstrations for PHISH-X.

This is deliberately separate from the existing Newton-optimized logistic model.
The baseline is a regularized straight-line least-squares score solved with
Gaussian elimination; its clipped outputs are scores, not calibrated probabilities.
"""
from __future__ import annotations

import time
from typing import Callable

import numpy as np

from phishx.data.preprocessing import NumericalStandardScaler


def gaussian_elimination(A, b):
    A = np.asarray(A, dtype=float).copy()
    b = np.asarray(b, dtype=float).reshape(-1).copy()
    n = len(b)
    if A.shape != (n, n):
        raise ValueError("A must be square and match b.")
    M = np.column_stack((A, b))
    for k in range(n):
        pivot = k + int(np.argmax(np.abs(M[k:, k])))
        if abs(M[pivot, k]) < 1e-12:
            raise ValueError("Singular or ill-conditioned system.")
        M[[k, pivot]] = M[[pivot, k]]
        for i in range(k + 1, n):
            factor = M[i, k] / M[k, k]
            M[i, k:] -= factor * M[k, k:]
    x = np.zeros(n)
    for i in range(n - 1, -1, -1):
        x[i] = (M[i, -1] - M[i, i + 1:n] @ x[i + 1:n]) / M[i, i]
    return x


def jacobi(A, b, tol=1e-10, max_iter=10000):
    A, b = np.asarray(A, float), np.asarray(b, float)
    if np.any(np.abs(np.diag(A)) < 1e-12):
        raise ValueError("Jacobi requires non-zero diagonal entries.")
    D = np.diag(A)
    R = A - np.diagflat(D)
    x = np.zeros_like(b, dtype=float)
    for iteration in range(1, max_iter + 1):
        new_x = (b - R @ x) / D
        if np.linalg.norm(new_x - x, ord=np.inf) < tol:
            return new_x, iteration
        x = new_x
    return x, max_iter


def bisection(f: Callable, a, b, tol=1e-10, max_iter=200):
    a, b = float(a), float(b)
    if f(a) * f(b) > 0:
        raise ValueError("The interval must bracket a root.")
    for i in range(1, max_iter + 1):
        c = (a + b) / 2
        if abs(f(c)) < tol or (b - a) / 2 < tol:
            return c, i
        if f(a) * f(c) < 0:
            b = c
        else:
            a = c
    return (a + b) / 2, max_iter


def newton_root(f, df, x, tol=1e-10, max_iter=100):
    x = float(x)
    for i in range(1, max_iter + 1):
        slope = df(x)
        if abs(slope) < 1e-14:
            raise ValueError("Derivative is too close to zero.")
        nxt = x - f(x) / slope
        if abs(nxt - x) < tol:
            return nxt, i
        x = nxt
    return x, max_iter


def secant(f, x0, x1, tol=1e-10, max_iter=100):
    x0, x1 = float(x0), float(x1)
    for i in range(1, max_iter + 1):
        denominator = f(x1) - f(x0)
        if abs(denominator) < 1e-14:
            raise ValueError("Secant denominator is too close to zero.")
        x2 = x1 - f(x1) * (x1 - x0) / denominator
        if abs(x2 - x1) < tol:
            return x2, i
        x0, x1 = x1, x2
    return x1, max_iter


def fixed_point(g, x, tol=1e-10, max_iter=1000):
    x = float(x)
    for i in range(1, max_iter + 1):
        nxt = float(g(x))
        if abs(nxt - x) < tol:
            return nxt, i
        x = nxt
    return x, max_iter


def trapezoidal(x, y):
    x, y = np.asarray(x, float), np.asarray(y, float)
    return float(np.sum((y[1:] + y[:-1]) * np.diff(x) / 2.0))


def simpson_one_third(x, y):
    x, y = np.asarray(x, float), np.asarray(y, float)
    if len(x) < 3 or len(x) % 2 == 0:
        raise ValueError("Simpson 1/3 requires an odd number of equally spaced points.")
    h = np.diff(x)
    if not np.allclose(h, h[0]):
        raise ValueError("Simpson 1/3 requires equally spaced points.")
    return float(h[0] / 3 * (y[0] + y[-1] + 4 * y[1:-1:2].sum() + 2 * y[2:-1:2].sum()))


def fit_straight_line(x, y):
    X = np.column_stack((np.ones(len(x)), np.asarray(x, float)))
    return gaussian_elimination(X.T @ X, X.T @ np.asarray(y, float))


def fit_quadratic(x, y):
    X = np.column_stack((np.ones(len(x)), np.asarray(x, float), np.asarray(x, float) ** 2))
    return gaussian_elimination(X.T @ X, X.T @ np.asarray(y, float))


def fit_exponential(x, y):
    y = np.asarray(y, float)
    if np.any(y <= 0):
        raise ValueError("Exponential fitting requires positive y values.")
    intercept, slope = fit_straight_line(x, np.log(y))
    return float(np.exp(intercept)), float(slope)


def lagrange_interpolate(x, y, target):
    x, y = np.asarray(x, float), np.asarray(y, float)
    total = 0.0
    for i in range(len(x)):
        basis = 1.0
        for j in range(len(x)):
            if i != j:
                basis *= (target - x[j]) / (x[i] - x[j])
        total += y[i] * basis
    return float(total)


def divided_differences(x, y):
    x, work = np.asarray(x, float), np.asarray(y, float).copy()
    coefficients = [float(work[0])]
    for order in range(1, len(x)):
        work = (work[1:] - work[:-1]) / (x[order:] - x[:-order])
        coefficients.append(float(work[0]))
    return coefficients


def newton_divided_eval(x, coefficients, target):
    value = coefficients[-1]
    for i in range(len(coefficients) - 2, -1, -1):
        value = coefficients[i] + (target - x[i]) * value
    return float(value)


def newton_forward(x, y, target):
    x, y = np.asarray(x, float), np.asarray(y, float)
    if len(x) < 2 or not np.allclose(np.diff(x), np.diff(x)[0]):
        raise ValueError("Forward differences require equally spaced x values.")
    h = x[1] - x[0]
    u = (target - x[0]) / h
    diff = y.copy()
    result, product = float(y[0]), 1.0
    for order in range(1, len(y)):
        diff = np.diff(diff)
        product *= (u - order + 1) / order
        result += product * diff[0]
    return float(result)


def newton_backward(x, y, target):
    x, y = np.asarray(x, float), np.asarray(y, float)
    if len(x) < 2 or not np.allclose(np.diff(x), np.diff(x)[0]):
        raise ValueError("Backward differences require equally spaced x values.")
    h = x[1] - x[0]
    u = (target - x[-1]) / h
    diff = y.copy()
    result, product = float(y[-1]), 1.0
    for order in range(1, len(y)):
        diff = np.diff(diff)
        product *= (u + order - 1) / order
        result += product * diff[-1]
    return float(result)


def train_numerical_model(X_train, y_train, ridge=1e-3):
    scaler = NumericalStandardScaler()
    Xs = scaler.fit_transform(np.asarray(X_train, float))
    # Dataset convention: 0 = phishing, 1 = legitimate.
    target = (np.asarray(y_train).reshape(-1) == 0).astype(float)
    design = np.column_stack((np.ones(len(Xs)), Xs))
    lhs = design.T @ design
    penalty = np.eye(lhs.shape[0]) * float(ridge)
    penalty[0, 0] = 0.0
    coefficients = gaussian_elimination(lhs + penalty, design.T @ target)
    return {"scaler": scaler, "coefficients": coefficients}


def predict_numerical_score(model, X):
    Xs = model["scaler"].transform(np.asarray(X, float))
    design = np.column_stack((np.ones(len(Xs)), Xs))
    return np.clip(design @ model["coefficients"], 0.0, 1.0)


def evaluate_numerical_model(model, X, y):
    start = time.perf_counter()
    scores = predict_numerical_score(model, X)
    elapsed = time.perf_counter() - start
    truth = (np.asarray(y).reshape(-1) == 0)
    pred = scores >= 0.5
    tp, fn = int(np.sum(pred & truth)), int(np.sum(~pred & truth))
    fp, tn = int(np.sum(pred & ~truth)), int(np.sum(~pred & ~truth))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(truth) if len(truth) else 0.0

    # ROC points from unique score thresholds; sort by FPR before integration.
    thresholds = np.r_[np.inf, np.sort(np.unique(scores))[::-1], -np.inf]
    positives, negatives = max(int(truth.sum()), 1), max(int((~truth).sum()), 1)
    points = []
    for threshold in thresholds:
        selected = scores >= threshold
        points.append((np.sum(selected & ~truth) / negatives,
                       np.sum(selected & truth) / positives))
    points = np.asarray(sorted(points, key=lambda pair: pair[0]))
    fpr = np.maximum.accumulate(points[:, 0])
    tpr = points[:, 1]
    auc_trap = float(np.sum((tpr[1:] + tpr[:-1]) * np.diff(fpr) / 2.0))
    grid = np.linspace(0.0, 1.0, 101)
    interp_tpr = np.interp(grid, fpr, tpr)
    auc_simpson = simpson_one_third(grid, interp_tpr)
    return {
        "accuracy": float(accuracy),
        "phishing_precision": float(precision),
        "phishing_recall": float(recall),
        "phishing_f1": float(f1),
        "confusion_matrix": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "roc_auc_trapezoidal": auc_trap,
        "roc_auc_simpson_1_3": auc_simpson,
        "inference_seconds": float(elapsed),
        "score_note": "Clipped least-squares score; not a calibrated probability.",
    }


def method_demos():
    f = lambda x: x * x - 2.0
    df = lambda x: 2.0 * x
    g = lambda x: 0.5 * (x + 2.0 / x)
    root = {
        "bisection": bisection(f, 1.0, 2.0),
        "newton": newton_root(f, df, 1.5),
        "secant": secant(f, 1.0, 2.0),
        "fixed_point": fixed_point(g, 1.5),
    }
    A = np.array([[4.0, 1.0], [2.0, 3.0]])
    b = np.array([9.0, 13.0])
    linear = {
        "gauss": gaussian_elimination(A, b).tolist(),
        "jacobi": jacobi(A, b)[0].tolist(),
    }
    x, y = [0., 1., 2., 3.], [1., 2., 5., 10.]
    interpolation = {
        "lagrange_at_1_5": lagrange_interpolate(x, y, 1.5),
        "newton_forward_at_1_5": newton_forward(x, y, 1.5),
        "newton_backward_at_1_5": newton_backward(x, y, 1.5),
    }
    integration_x = np.linspace(0.0, 1.0, 5)
    integration_y = integration_x ** 2
    integration = {
        "integral_x_squared_trapezoidal": trapezoidal(integration_x, integration_y),
        "integral_x_squared_simpson_1_3": simpson_one_third(integration_x, integration_y),
        "exact_integral": 1.0 / 3.0,
    }
    curve_x = np.array([0., 1., 2., 3.])
    curve_y = np.array([1., 3., 5., 7.])
    curve_fitting = {
        "straight_line_coefficients_intercept_slope": fit_straight_line(curve_x, curve_y).tolist(),
        "quadratic_coefficients_constant_linear_quadratic": fit_quadratic(curve_x, curve_y).tolist(),
        "exponential_coefficients_a_b_for_a_exp_bx": list(fit_exponential(curve_x, np.exp(0.5 + 0.2 * curve_x))),
    }
    return {
        "root_finding": root,
        "linear_systems": linear,
        "integration": integration,
        "curve_fitting": curve_fitting,
        "interpolation": interpolation,
    }
