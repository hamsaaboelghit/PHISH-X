"""Offline tests for the 5-feature baseline model and feature adapter.

No network access. Training tests use the fixed Group Split files and
small synthetic problems; they never visit a URL.
"""

import numpy as np
import pytest

from phishx.features.url_features import FEATURE_NAMES, extract_features
from phishx.models.baseline import (
    BASELINE_FEATURES,
    adapt_features,
    binary_cross_entropy,
    gradient_descent,
    newtons_method,
    sigmoid,
    train_baseline,
)


# ------------------------------------------------------------------- math


def test_sigmoid_known_values():
    assert sigmoid(np.array([0.0]))[0] == pytest.approx(0.5)
    assert sigmoid(np.array([1000.0]))[0] == pytest.approx(1.0)
    assert sigmoid(np.array([-1000.0]))[0] == pytest.approx(0.0)
    # Symmetry: sigmoid(-z) == 1 - sigmoid(z).
    z = np.array([0.3, 2.0, -1.5])
    assert np.allclose(sigmoid(-z), 1.0 - sigmoid(z))


def test_binary_cross_entropy_known_values():
    # Perfect predictions -> ~0 loss.
    assert binary_cross_entropy([1, 0], [1.0, 0.0]) == pytest.approx(0.0, abs=1e-9)
    # Worst predictions -> large loss (clipped, finite).
    loss = binary_cross_entropy([1, 0], [0.0, 1.0])
    assert np.isfinite(loss) and loss > 30
    # Coin-flip predictions -> ln(2).
    assert binary_cross_entropy([1, 0], [0.5, 0.5]) == pytest.approx(np.log(2))


def test_optimizers_converge_on_synthetic_problem():
    rng = np.random.default_rng(42)
    X = rng.normal(size=(300, 3))
    true_w = np.array([1.5, -2.0, 0.5])
    y = (sigmoid(X @ true_w) > rng.random(300)).astype(float)

    w_gd, hist_gd = gradient_descent(X, y, learning_rate=0.5, n_iterations=500)
    w_nw, hist_nw = newtons_method(X, y, n_iterations=50)

    # Both optimizers reduce the loss substantially.
    assert hist_gd[-1] < hist_gd[0]
    assert hist_nw[-1] < hist_nw[0]
    # Newton converges in far fewer iterations than GD.
    assert len(hist_nw) < len(hist_gd)
    # Both recover the direction of the true weights.
    assert np.allclose(np.sign(w_gd[:3]), np.sign(true_w))
    assert np.allclose(np.sign(w_nw[:3]), np.sign(true_w))


# ---------------------------------------------------------------- adapter


def test_adapter_selects_by_name_in_baseline_order():
    r = extract_features("http://192.168.0.1:8080/login.exe")
    assert r.ok
    vec = adapt_features(r.features)
    assert len(vec) == 5
    for i, name in enumerate(BASELINE_FEATURES):
        assert vec[i] == pytest.approx(r.features[name])
    # Baseline order differs from dataset order (documented contract).
    assert BASELINE_FEATURES != tuple(
        f for f in FEATURE_NAMES if f in BASELINE_FEATURES
    )


def test_adapter_refuses_missing_features():
    with pytest.raises(KeyError):
        adapt_features({"url_length": 10})


# ------------------------------------------------------- training / serving


@pytest.fixture(scope="module")
def gd_model():
    return train_baseline("gradient_descent")


@pytest.fixture(scope="module")
def nw_model():
    return train_baseline("newtons_method")


def test_training_is_deterministic_and_sane(gd_model):
    again = train_baseline("gradient_descent")
    assert np.allclose(gd_model.weights, again.weights)
    assert gd_model.n_iterations == 1000
    assert 0.0 < gd_model.final_loss < 0.5
    assert gd_model.train_accuracy > 0.9
    assert gd_model.test_accuracy > 0.9


def test_newton_converges_in_fewer_iterations(gd_model, nw_model):
    assert nw_model.n_iterations < gd_model.n_iterations
    assert nw_model.final_loss <= gd_model.final_loss + 1e-9


def test_prediction_label_semantics(gd_model):
    # 0 = Phishing, 1 = Legitimate: output is P(Legitimate).
    ip_url = extract_features("http://192.168.0.1:8080/login.exe").features
    legit_url = extract_features("https://www.example.com/").features
    p_ip = gd_model.predict_proba_legitimate(ip_url)
    p_legit = gd_model.predict_proba_legitimate(legit_url)
    assert 0.0 <= p_ip <= 1.0 and 0.0 <= p_legit <= 1.0
    # The IP-hosted URL must score lower P(Legitimate) than the plain domain.
    assert p_ip < p_legit
    cls, conf = gd_model.predict(ip_url)
    assert cls in ("Phishing", "Legitimate")
    assert 0.5 <= conf <= 1.0
    # Confidence is the probability of the predicted class.
    if cls == "Legitimate":
        assert conf == pytest.approx(p_ip)
    else:
        assert conf == pytest.approx(1.0 - p_ip)


def test_explanation_covers_all_five_features(gd_model):
    feats = extract_features("http://a.com/login").features
    expl = gd_model.explain(feats)
    assert sorted(n for n, _ in expl) == sorted(BASELINE_FEATURES)
    # Sorted by absolute contribution, largest first.
    absvals = [abs(v) for _, v in expl]
    assert absvals == sorted(absvals, reverse=True)


def test_analyze_url_pipeline(gd_model):
    from phishx.models.baseline import analyze_url

    out = analyze_url("http://192.168.0.1:8080/login.exe", gd_model)
    assert out["extraction_ok"] and out["prediction"] == "Phishing"
    assert out["features"] is not None and len(out["features"]) == 16
    assert out["signals"]["parsed"] is True
    assert out["explanation"] is not None

    # Invalid input: no prediction, never a confident benign verdict.
    bad = analyze_url("", gd_model)
    assert not bad["extraction_ok"]
    assert bad["prediction"] is None and bad["confidence"] is None


def test_opaque_schemes_get_no_prediction(gd_model):
    from phishx.models.baseline import analyze_url

    # Opaque schemes are out of distribution (training data is
    # http/https only): extraction succeeds but no prediction is offered.
    for url in ("javascript:alert(1)", "data:text/html,hi", "mailto:a@b.example"):
        out = analyze_url(url, gd_model)
        assert out["extraction_ok"], url
        assert out["signals"]["is_opaque_scheme"], url
        assert out["prediction"] is None, url
        assert out["no_prediction_reason"], url
