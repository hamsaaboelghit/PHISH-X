
from pathlib import Path
import json
import os
from urllib.parse import urlsplit
from collections import Counter
import html
import ipaddress
import math
import re

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


# ============================================================
# PHISH-X | THREAT INTELLIGENCE PLATFORM
# ============================================================

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "data" / "raw" / "url_features_extracted1.csv"

DEFAULT_MODEL_ARTIFACT = (
    ROOT / "data" / "processed" / "model_artifacts" / "phishx_newton_model.joblib"
)
_configured_artifact = Path(
    os.environ.get("PHISHX_MODEL_ARTIFACT", str(DEFAULT_MODEL_ARTIFACT))
).expanduser()
MODEL_ARTIFACT_PATH = (
    _configured_artifact
    if _configured_artifact.is_absolute()
    else ROOT / _configured_artifact
)
METRICS_PATH = ROOT / "data" / "processed" / "model_artifacts" / "training_metrics.json"


st.set_page_config(
    page_title="PHISH-X | Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_resource(show_spinner=False)
def load_phishx_model(artifact_path: str):
    """Load the trusted local PHISH-X model artifact once per app process."""
    import sys

    source_root = str(ROOT / "src")
    if source_root not in sys.path:
        sys.path.insert(0, source_root)

    from phishx.inference import load_model_artifact

    return load_model_artifact(artifact_path)

# ============================================================
# DESIGN SYSTEM
# ============================================================

BG = "#080D16"
PANEL = "#101927"
PANEL_2 = "#131F30"
BORDER = "#1F3044"
CYAN = "#20D9E6"
BLUE = "#3987FF"
PURPLE = "#9B7BFF"
GREEN = "#31D69B"
RED = "#FF5577"
MUTED = "#8192A8"
WHITE = "#EDF5FF"


st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Space+Mono:wght@400;700&display=swap');

    :root {
        --bg: #080D16;
        --panel: #101927;
        --panel2: #131F30;
        --border: #1F3044;
        --cyan: #20D9E6;
        --blue: #3987FF;
        --purple: #9B7BFF;
        --text: #EDF5FF;
        --muted: #8192A8;
    }

    html, body, [data-testid="stAppViewContainer"] {
        background: var(--bg);
        color: var(--text);
        font-family: 'Inter', sans-serif;
    }

    [data-testid="stHeader"] {
        background: rgba(8,13,22,0.85);
    }

    [data-testid="stAppViewContainer"] > .main {
        background:
            radial-gradient(ellipse at 15% 0%, rgba(32,217,230,0.055), transparent 35%),
            radial-gradient(ellipse at 90% 10%, rgba(155,123,255,0.055), transparent 30%),
            var(--bg);
    }

    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1600px;
    }

    /* Hide Streamlit auto-discovered navigation; PHISH-X has its own WORKSPACE radio. */
    [data-testid="stSidebarNav"],
    [data-testid="stAppNav"],
    [data-testid="stAppNavContainer"],
    [data-testid="stPageLink-NavLink"] {
        display: none !important;
    }

    [data-testid="stSidebar"] {
        background: #0B1320;
        border-right: 1px solid #1B2B3F;
    }

    [data-testid="stSidebar"] > div:first-child {
        padding-top: 1.5rem;
    }

    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
        color: #A8B7CA;
    }

    [data-testid="stSidebar"] .stRadio label {
        padding: 9px 12px;
        border-radius: 9px;
    }

    [data-testid="stSidebar"] .stRadio label:hover {
        background: #142338;
    }

    [data-testid="stSidebar"] [data-testid="stRadio"] > div {
        gap: 7px;
    }

    h1, h2, h3 {
        color: var(--text) !important;
        letter-spacing: -0.6px;
    }

    h1 {
        font-weight: 800 !important;
    }

    h2, h3 {
        font-weight: 700 !important;
    }

    p, label, span {
        font-family: 'Inter', sans-serif;
    }

    [data-testid="stMetric"] {
        background: linear-gradient(145deg, #121F30, #0E1826);
        border: 1px solid var(--border);
        border-radius: 13px;
        padding: 17px 19px;
        min-height: 112px;
    }

    [data-testid="stMetricLabel"] {
        color: #91A3B9 !important;
        font-size: 0.82rem !important;
    }

    [data-testid="stMetricValue"] {
        color: #F1F7FF !important;
        font-weight: 800 !important;
    }

    [data-testid="stMetricDelta"] {
        font-size: 0.76rem !important;
    }

    div[data-testid="stVerticalBlockBorderWrapper"] {
        background: rgba(16,25,39,0.8);
        border: 1px solid var(--border);
        border-radius: 14px;
    }

    .eyebrow {
        color: var(--cyan);
        text-transform: uppercase;
        letter-spacing: 2.5px;
        font-size: 0.72rem;
        font-weight: 800;
        margin-bottom: 8px;
    }

    .page-title {
        color: #F2F7FF;
        font-size: 2.25rem;
        font-weight: 800;
        letter-spacing: -1.2px;
        margin: 0;
    }

    .page-subtitle {
        color: #8FA2B9;
        font-size: 0.96rem;
        margin-top: 8px;
        margin-bottom: 25px;
    }

    .brand {
        font-size: 1.65rem;
        font-weight: 800;
        letter-spacing: 1.5px;
        color: #F2F7FF;
    }

    .brand span {
        color: var(--cyan);
    }

    .brand-sub {
        font-size: 0.65rem;
        color: #8093AA;
        letter-spacing: 2.1px;
        margin-top: 2px;
    }

    .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 7px;
        padding: 6px 11px;
        border-radius: 30px;
        border: 1px solid rgba(49,214,155,0.25);
        background: rgba(49,214,155,0.08);
        color: #63E7B7;
        font-size: 0.72rem;
        font-weight: 700;
    }

    .status-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: #31D69B;
        box-shadow: 0 0 9px #31D69B;
    }

    .section-label {
        color: #A9B9CC;
        font-size: 0.77rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1.6px;
        margin: 12px 0 14px 0;
    }

    .info-card {
        background: linear-gradient(145deg, #121F30, #0D1724);
        border: 1px solid #20334A;
        border-radius: 13px;
        padding: 18px;
        height: 100%;
    }

    .info-card .card-label {
        color: #8EA2BA;
        font-size: 0.76rem;
        margin-bottom: 10px;
    }

    .info-card .card-value {
        color: #F2F7FF;
        font-size: 1.35rem;
        font-weight: 800;
    }

    .info-card .card-note {
        color: #8092A8;
        font-size: 0.76rem;
        margin-top: 8px;
    }

    .accent-line {
        height: 3px;
        width: 42px;
        background: linear-gradient(90deg, var(--cyan), var(--blue));
        border-radius: 5px;
        margin: 10px 0 18px 0;
    }

    .hero {
        position: relative;
        overflow: hidden;
        background: linear-gradient(115deg, #10273A 0%, #111D32 52%, #211A3B 100%);
        border: 1px solid #29445D;
        border-radius: 18px;
        padding: 27px 30px;
        margin-bottom: 24px;
    }

    .hero::after {
        content: "";
        position: absolute;
        width: 260px;
        height: 260px;
        right: -80px;
        top: -130px;
        border-radius: 50%;
        border: 1px solid rgba(32,217,230,0.18);
        box-shadow: 0 0 0 25px rgba(32,217,230,0.025),
                    0 0 0 55px rgba(32,217,230,0.02);
    }

    .hero-kicker {
        color: var(--cyan);
        font-family: 'Space Mono', monospace;
        font-size: 0.72rem;
        letter-spacing: 2px;
        margin-bottom: 10px;
    }

    .hero-title {
        color: #F5FAFF;
        font-size: 1.75rem;
        font-weight: 800;
        margin-bottom: 8px;
    }

    .hero-text {
        color: #A9BED1;
        font-size: 0.9rem;
        max-width: 680px;
        line-height: 1.7;
    }

    .hero-tag {
        display: inline-block;
        border: 1px solid rgba(32,217,230,0.25);
        background: rgba(32,217,230,0.08);
        color: #72EAF0;
        border-radius: 6px;
        padding: 5px 9px;
        font-family: 'Space Mono', monospace;
        font-size: 0.68rem;
        margin-right: 6px;
        margin-top: 14px;
    }

    .url-result {
        background: #101C2A;
        border: 1px solid #294057;
        border-radius: 13px;
        padding: 20px;
        margin-top: 15px;
    }

    .url-result-title {
        color: #91A6BD;
        font-size: 0.76rem;
        text-transform: uppercase;
        letter-spacing: 1.4px;
        margin-bottom: 10px;
    }

    .url-result-value {
        color: #F2F7FF;
        font-family: 'Space Mono', monospace;
        font-size: 0.88rem;
        overflow-wrap: anywhere;
    }

    .stButton > button {
        background: linear-gradient(100deg, #13BFCF, #347CF2);
        color: #06121E;
        border: none;
        border-radius: 9px;
        font-weight: 800;
        padding: 0.62rem 1.25rem;
        transition: 0.2s ease;
    }

    .stButton > button:hover {
        box-shadow: 0 0 22px rgba(32,217,230,0.22);
        border: none;
        color: #06121E;
        transform: translateY(-1px);
    }

    .stTextInput input, .stNumberInput input {
        background: #0D1927;
        border: 1px solid #2A3C51;
        color: #F2F7FF;
        border-radius: 9px;
    }

    [data-baseweb="select"] > div {
        background: #0D1927;
        border-color: #2A3C51;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid #25374B;
        border-radius: 10px;
        overflow: hidden;
    }

    hr {
        border-color: #203047;
    }

    .footer {
        color: #63768D;
        font-size: 0.72rem;
        text-align: center;
        padding-top: 25px;
        letter-spacing: 0.4px;
    }

    #MainMenu, footer {
        visibility: hidden;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# DATA
# ============================================================

@st.cache_data
def load_data():
    if not DATA_PATH.exists():
        return None

    df = pd.read_csv(DATA_PATH)

    if "ClassLabel" in df.columns:
        df["ClassLabel"] = pd.to_numeric(
            df["ClassLabel"], errors="coerce"
        )

    return df


df = load_data()

if df is not None:
    if "ClassLabel" in df.columns:
        df["ClassName"] = df["ClassLabel"].map({
            0: "Phishing",
            1: "Legitimate",
        })
    else:
        df["ClassName"] = "Unknown"


# ============================================================
# PLOTLY THEME
# ============================================================

def style_chart(fig, height=330):
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(
            family="Inter",
            color="#AFC0D3",
            size=11,
        ),
        margin=dict(l=15, r=15, t=35, b=15),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            borderwidth=0,
        ),
        xaxis=dict(
            gridcolor="#1C2B3D",
            zerolinecolor="#1C2B3D",
            linecolor="#26394E",
        ),
        yaxis=dict(
            gridcolor="#1C2B3D",
            zerolinecolor="#1C2B3D",
            linecolor="#26394E",
        ),
    )
    return fig


def section_title(title, subtitle=None):
    st.markdown(f'<div class="section-label">{title}</div>', unsafe_allow_html=True)
    if subtitle:
        st.caption(subtitle)


def page_header(kicker, title, subtitle):
    st.markdown(
        f"""
        <div class="eyebrow">{kicker}</div>
        <div class="page-title">{title}</div>
        <div class="page-subtitle">{subtitle}</div>
        """,
        unsafe_allow_html=True,
    )


def metric_card(label, value, note=""):
    st.markdown(
        f"""
        <div class="info-card">
            <div class="card-label">{label}</div>
            <div class="card-value">{value}</div>
            <div class="card-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def safe_hostname(url):
    try:
        candidate = url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
            candidate = "http://" + candidate

        parsed = urlsplit(candidate)
        return parsed.hostname or ""
    except (ValueError, AttributeError):
        return ""


def extract_basic_signals(url):
    normalized = url.strip()

    try:
        parsed_url = normalized
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", parsed_url):
            parsed_url = "http://" + parsed_url

        parsed = urlsplit(parsed_url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""

        is_ip = False
        if hostname:
            try:
                ipaddress.ip_address(hostname)
                is_ip = True
            except ValueError:
                pass

        return {
            "URL length": len(normalized),
            "HTTPS": int(parsed.scheme.lower() == "https"),
            "IP address in hostname": int(is_ip),
            "Dots in full URL": normalized.count("."),
            "Digits in URL": sum(c.isdigit() for c in normalized),
            "Hyphen in hostname": int("-" in hostname),
            "Path length": len(path),
            "Query parameters": len(
                [x for x in query.split("&") if x]
            ),
            "Hostname length": len(hostname),
        }

    except ValueError:
        return {}


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.markdown(
        """
        <div style="padding: 5px 4px 24px 4px;">
            <div style="font-size:2rem; margin-bottom:4px;">◈</div>
            <div class="brand">PHISH<span>-X</span></div>
            <div class="brand-sub">THREAT INTELLIGENCE PLATFORM</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="section-label">WORKSPACE</div>',
        unsafe_allow_html=True,
    )

    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Dataset Intelligence",
            "Model Evaluation",
            "Optimization Lab",
            "URL Investigation",
        ],
        label_visibility="collapsed",
    )

    st.divider()

    st.markdown(
        """
        <div style="font-size:0.7rem;color:#71849B;letter-spacing:1.4px;font-weight:700;">
            SYSTEM STATUS
        </div>
        """,
        unsafe_allow_html=True,
    )

    if df is not None:
        st.markdown(
            """
            <div style="display:flex;align-items:center;gap:8px;margin-top:12px;">
                <span class="status-dot"></span>
                <span style="font-size:0.8rem;color:#A8B9CA;">Dataset connected</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<span style="color:#FF8299;font-size:0.8rem;">Dataset not found</span>',
            unsafe_allow_html=True,
        )

    st.markdown(
        """
        <div style="margin-top:35px;padding-top:15px;border-top:1px solid #203047;">
            <div style="color:#6E829A;font-size:0.68rem;letter-spacing:1px;">
                PROJECT
            </div>
            <div style="color:#C4D2E2;font-size:0.8rem;margin-top:7px;">
                PHISH-X v1.0
            </div>
            <div style="color:#6E829A;font-size:0.68rem;margin-top:5px;">
                Explainable AI • Numerical Methods
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# DATA CHECK
# ============================================================

if df is None:
    st.error(
        "Dataset not found. Make sure the CSV file is located at "
        "`data/raw/url_features_extracted1.csv`."
    )
    st.stop()

if "ClassLabel" not in df.columns:
    st.error("The dataset does not contain the required ClassLabel column.")
    st.stop()


valid_labels = df["ClassLabel"].dropna()
phishing_count = int((valid_labels == 0).sum())
legitimate_count = int((valid_labels == 1).sum())
unknown_count = int((~valid_labels.isin([0, 1])).sum())
total_records = len(df)
valid_count = len(valid_labels)

feature_columns = [
    col for col in df.columns
    if col not in ["URL", "ClassLabel", "ClassName", "source_record"]
    and pd.api.types.is_numeric_dtype(df[col])
]

duplicate_count = int(df["URL"].duplicated().sum()) if "URL" in df.columns else 0


# ============================================================
# PAGE 1 — OVERVIEW
# ============================================================

if page == "Overview":

    page_header(
        "THREAT INTELLIGENCE / OVERVIEW",
        "Security Operations Overview",
        "A central view of phishing intelligence, dataset composition and analytical readiness.",
    )

    st.markdown(
        """
        <div class="hero">
            <div class="hero-kicker">◈ PHISH-X / INTELLIGENCE CORE</div>
            <div class="hero-title">See the threat. Understand the signal.</div>
            <div class="hero-text">
                An explainable phishing URL analysis platform combining
                machine learning, numerical optimization and cybersecurity
                intelligence to investigate suspicious URLs.
            </div>
            <span class="hero-tag">URL INTELLIGENCE</span>
            <span class="hero-tag">EXPLAINABLE AI</span>
            <span class="hero-tag">NUMERICAL METHODS</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    section_title("DATASET SNAPSHOT", "Current statistics from the loaded dataset.")

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric("Total URLs", f"{total_records:,}")

    with c2:
        st.metric("Phishing URLs", f"{phishing_count:,}")

    with c3:
        st.metric("Legitimate URLs", f"{legitimate_count:,}")

    with c4:
        st.metric("Extracted Features", len(feature_columns))

    st.markdown("<br>", unsafe_allow_html=True)

    left, right = st.columns([1.15, 0.85], gap="large")

    with left:
        with st.container(border=True):
            section_title("CLASS DISTRIBUTION", "How the available records are distributed.")

            class_data = pd.DataFrame({
                "Class": ["Phishing", "Legitimate"],
                "Records": [phishing_count, legitimate_count],
            })

            fig = go.Figure(
                go.Pie(
                    labels=class_data["Class"],
                    values=class_data["Records"],
                    hole=0.72,
                    marker=dict(
                        colors=[RED, CYAN],
                        line=dict(color=BG, width=4),
                    ),
                    textinfo="label+percent",
                    textfont=dict(color=WHITE, size=12),
                    hovertemplate="%{label}<br>%{value:,} records<extra></extra>",
                )
            )

            fig.add_annotation(
                text=f"<b>{valid_count:,}</b><br><span style='font-size:11px'>VALID LABELS</span>",
                x=0.5,
                y=0.5,
                showarrow=False,
                font=dict(size=20, color=WHITE),
            )

            fig.update_layout(
                height=330,
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color=WHITE),
                margin=dict(l=10, r=10, t=15, b=10),
                showlegend=False,
            )

            st.plotly_chart(fig, width="stretch")

    with right:
        with st.container(border=True):
            section_title("DATA QUALITY SIGNALS", "Initial checks from the raw dataset.")

            quality_items = [
                ("Missing labels", int(df["ClassLabel"].isna().sum()), RED),
                ("Duplicate URLs", duplicate_count, PURPLE),
                ("Unknown labels", unknown_count, RED),
                ("Numeric features", len(feature_columns), CYAN),
            ]

            for label, value, color in quality_items:
                st.markdown(
                    f"""
                    <div style="display:flex;justify-content:space-between;
                    align-items:center;padding:14px 0;border-bottom:1px solid #203047;">
                        <span style="color:#A5B6C9;font-size:0.86rem;">{label}</span>
                        <span style="color:{color};font-weight:800;font-size:1rem;">{value:,}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.markdown(
                """
                <div style="margin-top:15px;color:#8192A8;font-size:0.75rem;line-height:1.6;">
                    These are preliminary data-quality indicators.
                    They do not represent model performance.
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    section_title("INTELLIGENCE WORKSPACE", "Navigate through the platform.")

    a, b, c = st.columns(3)

    with a:
        metric_card("01 / DATASET", "Intelligence", "Explore features, labels and dataset quality.")

    with b:
        metric_card("02 / NUMERICAL", "Optimization Lab", "Compare numerical optimization methods.")

    with c:
        metric_card("03 / SECURITY", "URL Investigation", "Inspect URL structure and extracted signals.")


# ============================================================
# PAGE 2 — DATASET INTELLIGENCE
# ============================================================

elif page == "Dataset Intelligence":

    page_header(
        "DATA INTELLIGENCE / DATASET AUDIT",
        "Dataset Intelligence",
        "Investigate class composition, feature distributions and potential data-quality risks.",
    )

    tab1, tab2, tab3, tab4 = st.tabs([
        "Class Analysis",
        "Feature Explorer",
        "TLD Intelligence",
        "Data Quality",
    ])

    # --------------------------------------------------------
    # CLASS ANALYSIS
    # --------------------------------------------------------

    with tab1:

        section_title("CLASS COMPOSITION")

        col1, col2 = st.columns(2)

        with col1:
            st.metric("Phishing", f"{phishing_count:,}")

        with col2:
            st.metric("Legitimate", f"{legitimate_count:,}")

        class_data = pd.DataFrame({
            "Class": ["Phishing", "Legitimate"],
            "Records": [phishing_count, legitimate_count],
        })

        fig = px.bar(
            class_data,
            x="Class",
            y="Records",
            color="Class",
            color_discrete_map={
                "Phishing": RED,
                "Legitimate": CYAN,
            },
            text="Records",
        )

        fig.update_traces(texttemplate="%{text:,}", textposition="outside")
        fig = style_chart(fig, 350)
        fig.update_layout(showlegend=False)

        st.plotly_chart(fig, width="stretch")

        st.markdown(
            """
            <div class="info-card">
                <div class="card-label">LABEL INTERPRETATION</div>
                <div style="color:#EAF3FF;font-weight:700;margin-bottom:8px;">
                    0 = Phishing &nbsp;&nbsp; | &nbsp;&nbsp; 1 = Legitimate
                </div>
                <div class="card-note">
                    This mapping follows the dataset's documented label convention.
                    The single missing label is excluded from class counts.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # --------------------------------------------------------
    # FEATURE EXPLORER
    # --------------------------------------------------------

    with tab2:

        section_title("FEATURE EXPLORER", "Inspect numerical feature behavior by class.")

        if feature_columns:

            selected_feature = st.selectbox(
                "Select a feature",
                feature_columns,
            )

            plot_df = df[
                df["ClassLabel"].isin([0, 1])
            ][["ClassLabel", selected_feature]].copy()

            plot_df["Class"] = plot_df["ClassLabel"].map({
                0: "Phishing",
                1: "Legitimate",
            })

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric(
                    "Mean",
                    f"{plot_df[selected_feature].mean():.3f}",
                )

            with col2:
                st.metric(
                    "Median",
                    f"{plot_df[selected_feature].median():.3f}",
                )

            with col3:
                st.metric(
                    "Standard Deviation",
                    f"{plot_df[selected_feature].std():.3f}",
                )

            fig = px.histogram(
                plot_df,
                x=selected_feature,
                color="Class",
                marginal="box",
                barmode="overlay",
                opacity=0.72,
                color_discrete_map={
                    "Phishing": RED,
                    "Legitimate": CYAN,
                },
                nbins=45,
            )

            fig = style_chart(fig, 430)
            st.plotly_chart(fig, width="stretch")

            stats = plot_df.groupby("Class")[selected_feature].agg(
                ["count", "mean", "median", "std", "min", "max"]
            )

            st.dataframe(
                stats.style.format("{:.3f}"),
                width="stretch",
            )

        else:
            st.warning("No numerical features are available.")

    # --------------------------------------------------------
    # TLD INTELLIGENCE
    # --------------------------------------------------------

    with tab3:

        section_title(
            "TOP-LEVEL DOMAIN INTELLIGENCE",
            "Explore domain suffix patterns in the dataset.",
        )

        if "URL" in df.columns:

            def get_tld(url):
                hostname = safe_hostname(str(url))
                if not hostname:
                    return "Unknown"

                try:
                    ipaddress.ip_address(hostname)
                    return "IP_ADDRESS"
                except ValueError:
                    pass

                labels = hostname.lower().rstrip(".").split(".")
                return labels[-1] if labels else "Unknown"

            tld_df = df[["URL", "ClassLabel"]].copy()
            tld_df["TLD"] = tld_df["URL"].astype(str).apply(get_tld)

            tld_counts = (
                tld_df["TLD"]
                .value_counts()
                .head(15)
                .rename_axis("TLD")
                .reset_index(name="Records")
            )

            fig = px.bar(
                tld_counts.sort_values("Records"),
                x="Records",
                y="TLD",
                orientation="h",
                color="Records",
                color_continuous_scale=["#17354B", CYAN, BLUE],
            )

            fig = style_chart(fig, 480)
            fig.update_layout(coloraxis_showscale=False)

            st.plotly_chart(fig, width="stretch")

            class_tld = (
                tld_df[tld_df["ClassLabel"].isin([0, 1])]
                .groupby(["TLD", "ClassLabel"])
                .size()
                .reset_index(name="Records")
            )

            class_tld["Class"] = class_tld["ClassLabel"].map({
                0: "Phishing",
                1: "Legitimate",
            })

            top_tlds = tld_counts["TLD"].head(12).tolist()
            class_tld = class_tld[class_tld["TLD"].isin(top_tlds)]

            fig = px.bar(
                class_tld,
                x="TLD",
                y="Records",
                color="Class",
                barmode="group",
                color_discrete_map={
                    "Phishing": RED,
                    "Legitimate": CYAN,
                },
            )

            fig = style_chart(fig, 400)
            st.plotly_chart(fig, width="stretch")

            st.caption(
                "Note: This is a simplified final-label extraction, not a full Public Suffix List parser."
            )

    # --------------------------------------------------------
    # DATA QUALITY
    # --------------------------------------------------------

    with tab4:

        section_title("DATA QUALITY AUDIT")

        missing = df.isna().sum()
        missing = missing[missing > 0].sort_values(ascending=False)

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Missing Values", f"{int(df.isna().sum().sum()):,}")

        with col2:
            st.metric("Duplicate URLs", f"{duplicate_count:,}")

        with col3:
            st.metric("Rows", f"{len(df):,}")

        left, right = st.columns(2)

        with left:
            st.markdown("**Missing values by column**")

            if len(missing):
                missing_df = missing.rename("Missing").reset_index()
                missing_df.columns = ["Column", "Missing"]
                st.dataframe(missing_df, width="stretch")
            else:
                st.success("No missing values detected.")

        with right:
            st.markdown("**Dataset structure**")

            schema_df = pd.DataFrame({
                "Column": df.columns,
                "Data type": df.dtypes.astype(str).values,
                "Missing": df.isna().sum().values,
            })

            st.dataframe(schema_df, width="stretch", height=300)

        st.markdown("<br>", unsafe_allow_html=True)

        if "URL" in df.columns:
            duplicate_rows = df[df["URL"].duplicated(keep=False)].copy()

            if len(duplicate_rows):
                st.markdown("**Duplicate URL samples**")
                st.dataframe(
                    duplicate_rows[["URL", "ClassLabel"]].head(20),
                    width="stretch",
                )

        st.warning(
            "Duplicate records and class composition require investigation "
            "before model training. This page does not automatically clean or modify the raw dataset."
        )




# ============================================================
# MODEL EVALUATION — HELD-OUT GROUP TEST SET
# ============================================================

elif page == "Model Evaluation":

    page_header(
        "MODEL VALIDATION / HELD-OUT TEST RESULTS",
        "Model Evaluation",
        "Performance measured on the held-out Group Test set, separated by URL class.",
    )

    if not METRICS_PATH.is_file():
        st.warning(
            "Training metrics are not available yet. Run "
            "`python src/phishx/models/train.py` from the project root "
            "to train the model and generate the evaluation report."
        )
    else:
        try:
            metrics_report = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
            evaluation = metrics_report["evaluation"]
            class_metrics = evaluation["class_metrics"]
            phishing_metrics = class_metrics["phishing"]
            legitimate_metrics = class_metrics["legitimate"]
            confusion = evaluation["confusion_matrix"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            st.error(
                "The evaluation report is missing required fields or is invalid. "
                f"Regenerate it by running the training script. Details: {exc}"
            )
        else:
            st.markdown(
                """
                <div class="hero">
                    <div class="hero-kicker">HELD-OUT VALIDATION</div>
                    <div class="hero-title">Measure detection quality, class by class.</div>
                    <div class="hero-text">
                        The test set is separated by hostname from the training set.
                        Phishing detection metrics are shown explicitly so they are
                        not confused with the Legitimate positive-class metrics.
                    </div>
                    <span class="hero-tag">GROUP SPLIT BY HOST</span>
                    <span class="hero-tag">CLASS-SPECIFIC METRICS</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            overview_cols = st.columns(4)
            overview_cols[0].metric("Test samples", f"{evaluation['samples']:,}")
            overview_cols[1].metric("Accuracy", f"{evaluation['accuracy']:.2%}")
            overview_cols[2].metric("Decision threshold", f"{evaluation['threshold']:.2f}")
            overview_cols[3].metric("Training iterations", str(metrics_report["training"]["iterations"]))

            st.markdown("<br>", unsafe_allow_html=True)
            section_title("PHISHING DETECTION", "The security-critical class: 0 = Phishing.")

            phishing_cols = st.columns(3)
            phishing_cols[0].metric("Phishing Precision", f"{phishing_metrics['precision']:.2%}")
            phishing_cols[1].metric("Phishing Recall", f"{phishing_metrics['recall']:.2%}")
            phishing_cols[2].metric("Phishing F1-score", f"{phishing_metrics['f1_score']:.2%}")

            section_title("LEGITIMATE CLASS", "Class 1 = Legitimate.")
            legitimate_cols = st.columns(3)
            legitimate_cols[0].metric("Legitimate Precision", f"{legitimate_metrics['precision']:.2%}")
            legitimate_cols[1].metric("Legitimate Recall", f"{legitimate_metrics['recall']:.2%}")
            legitimate_cols[2].metric("Legitimate F1-score", f"{legitimate_metrics['f1_score']:.2%}")

            st.markdown("<br>", unsafe_allow_html=True)
            left, right = st.columns([1, 1], gap="large")

            with left:
                section_title("CONFUSION MATRIX", "Actual class by predicted class.")
                confusion_frame = pd.DataFrame(
                    [
                        [confusion["true_negative"], confusion["false_positive"]],
                        [confusion["false_negative"], confusion["true_positive"]],
                    ],
                    index=["Actual Phishing", "Actual Legitimate"],
                    columns=["Predicted Phishing", "Predicted Legitimate"],
                )
                st.dataframe(confusion_frame, width="stretch")
                st.caption(
                    "True Negative = correctly detected Phishing; "
                    "True Positive = correctly identified Legitimate."
                )

            with right:
                section_title("EVALUATION SETUP")
                st.metric("Dataset split", metrics_report.get("dataset_split", "Not specified"))
                st.metric("Feature specification", metrics_report.get("feature_spec_version", "Not specified"))
                st.metric("Model optimizer", metrics_report["training"]["method"])
                st.metric("Regularization (L2)", f"{metrics_report['training']['l2']:.4g}")

            st.caption(
                "Metrics describe this held-out dataset split, not a guarantee of "
                "performance on every URL or on future phishing campaigns."
            )


# ============================================================
# PAGE 3 — OPTIMIZATION LAB
# ============================================================

elif page == "Optimization Lab":

    page_header(
        "NUMERICAL COMPUTATIONS / OPTIMIZATION",
        "Numerical Optimization Lab",
        "Run both hand-implemented optimizers on the same Group Train sample.",
    )

    st.markdown(
        """
        <div class="hero">
            <div class="hero-kicker">NUMERICAL METHODS ENGINE</div>
            <div class="hero-title">Compare the mathematics, not just the predictions.</div>
            <div class="hero-text">
                Both methods optimize the same Logistic Regression objective
                using the same scaled training sample and L2 regularization.
            </div>
            <span class="hero-tag">BATCH GRADIENT DESCENT</span>
            <span class="hero-tag">NEWTON-RAPHSON</span>
            <span class="hero-tag">BINARY CROSS-ENTROPY</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Experiment configuration")
    cfg1, cfg2, cfg3 = st.columns(3)
    with cfg1:
        sample_per_class = st.select_slider(
            "Samples per class",
            options=[500, 1000, 2000, 5000],
            value=2000,
        )
    with cfg2:
        learning_rate = st.select_slider(
            "Gradient Descent learning rate",
            options=[0.01, 0.03, 0.05, 0.1],
            value=0.05,
        )
    with cfg3:
        max_iterations = st.select_slider(
            "Maximum iterations",
            options=[100, 250, 500, 1000],
            value=500,
        )

    st.caption(
        "A deterministic, class-balanced sample is used for interactive runtime. "
        "The production model is trained separately on the complete Group Train split."
    )

    if st.button("Run numerical comparison", type="primary", width="stretch"):
        import sys
        import time

        import numpy as np

        source_root = str(ROOT / "src")
        if source_root not in sys.path:
            sys.path.insert(0, source_root)

        try:
            from phishx.data.dataset import load_group_split
            from phishx.data.preprocessing import NumericalStandardScaler
            from phishx.models.logistic_regression import (
                gradient_descent,
                newton_method,
            )

            with st.spinner("Loading Group Train and running both numerical methods..."):
                X_train, _, y_train, _ = load_group_split()
                X_frame = X_train.copy()
                y_series = y_train.copy()

                class_frames = []
                for label in (0, 1):
                    class_frame = X_frame.loc[y_series == label].copy()
                    class_frame["_target"] = y_series.loc[y_series == label].to_numpy()
                    if class_frame.empty:
                        raise ValueError(f"Training split does not contain class {label}.")
                    class_frames.append(
                        class_frame.sample(
                            n=min(sample_per_class, len(class_frame)),
                            random_state=42,
                        )
                    )

                experiment = (
                    pd.concat(class_frames, axis=0)
                    .sample(frac=1.0, random_state=42)
                    .reset_index(drop=True)
                )
                y_experiment = experiment.pop("_target").to_numpy(dtype=int)
                X_experiment = experiment.to_numpy(dtype=float)

                scaler = NumericalStandardScaler()
                X_scaled = scaler.fit_transform(X_experiment)

                gd_start = time.perf_counter()
                _, _, gd_losses = gradient_descent(
                    X_scaled,
                    y_experiment,
                    learning_rate=learning_rate,
                    n_iterations=max_iterations,
                    l2=1e-3,
                )
                gd_seconds = time.perf_counter() - gd_start

                newton_start = time.perf_counter()
                _, _, nr_losses = newton_method(
                    X_scaled,
                    y_experiment,
                    n_iterations=min(max_iterations, 100),
                    l2=1e-3,
                    damping=1e-8,
                    tolerance=1e-7,
                )
                newton_seconds = time.perf_counter() - newton_start

            st.session_state["phishx_optimization_result"] = {
                "gd_losses": [float(v) for v in gd_losses],
                "nr_losses": [float(v) for v in nr_losses],
                "gd_iterations": len(gd_losses) - 1,
                "nr_iterations": len(nr_losses) - 1,
                "gd_seconds": gd_seconds,
                "nr_seconds": newton_seconds,
                "gd_final_loss": float(gd_losses[-1]),
                "nr_final_loss": float(nr_losses[-1]),
                "samples": int(len(y_experiment)),
                "sample_per_class": int(sample_per_class),
                "learning_rate": float(learning_rate),
            }
            st.success("Both numerical experiments completed.")
        except Exception as exc:
            st.error(f"Optimization experiment failed: {exc}")

    result = st.session_state.get("phishx_optimization_result")
    if result:
        st.markdown("### Measured results")
        st.caption(
            f"Same balanced sample: {result['samples']:,} records | "
            f"L2 = 0.001 | GD learning rate = {result['learning_rate']}"
        )

        metric_cols = st.columns(4)
        metric_cols[0].metric("GD final loss", f"{result['gd_final_loss']:.6f}")
        metric_cols[1].metric("Newton final loss", f"{result['nr_final_loss']:.6f}")
        metric_cols[2].metric("GD iterations", result["gd_iterations"])
        metric_cols[3].metric("Newton iterations", result["nr_iterations"])

        metric_cols = st.columns(2)
        metric_cols[0].metric("GD runtime", f"{result['gd_seconds']:.3f} s")
        metric_cols[1].metric("Newton runtime", f"{result['nr_seconds']:.3f} s")

        convergence = pd.DataFrame(
            {
                "Iteration": list(range(len(result["gd_losses"])))
                + list(range(len(result["nr_losses"]))),
                "Loss": result["gd_losses"] + result["nr_losses"],
                "Method": (
                    ["Gradient Descent"] * len(result["gd_losses"])
                    + ["Newton-Raphson"] * len(result["nr_losses"])
                ),
            }
        )
        st.markdown("### Convergence curves")
        st.line_chart(
            convergence.pivot(
                index="Iteration",
                columns="Method",
                values="Loss",
            )
        )

        comparison = pd.DataFrame(
            [
                {
                    "Method": "Batch Gradient Descent",
                    "Iterations": result["gd_iterations"],
                    "Final BCE + L2": result["gd_final_loss"],
                    "Runtime (seconds)": result["gd_seconds"],
                },
                {
                    "Method": "Newton-Raphson",
                    "Iterations": result["nr_iterations"],
                    "Final BCE + L2": result["nr_final_loss"],
                    "Runtime (seconds)": result["nr_seconds"],
                },
            ]
        )
        st.dataframe(comparison, width="stretch", hide_index=True)

    with st.container(border=True):
        st.markdown("### Numerical objective and update equations")
        st.latex(
            r"J(w,b)=-\frac{1}{m}\sum_{i=1}^{m}"
            r"[y_i\log(p_i)+(1-y_i)\log(1-p_i)]"
            r"+\frac{\lambda}{2m}\|w\|_2^2"
        )
        st.markdown("**Gradient Descent**")
        st.latex(r"w_{k+1}=w_k-\alpha\nabla J(w_k)")
        st.markdown("**Newton-Raphson**")
        st.latex(r"\theta_{k+1}=\theta_k-H(\theta_k)^{-1}\nabla J(\theta_k)")
        st.caption(
            "The inverse-Hessian update is implemented through the project's "
            "manual linear solver (Gaussian Elimination with Partial Pivoting), "
            "not a library optimizer."
        )


# PAGE 4 — URL INVESTIGATION
# ============================================================

elif page == "URL Investigation":

    page_header(
        "SECURITY OPERATIONS / AI-POWERED URL ANALYSIS",
        "URL Investigation",
        "Run the trained Newton Logistic Regression model and inspect its explainable security assessment.",
    )

    st.markdown(
        """
        <div class="hero">
            <div class="hero-kicker">ANALYST WORKSPACE / ARTIFACT-BACKED INFERENCE</div>
            <div class="hero-title">Investigate a suspicious URL.</div>
            <div class="hero-text">
                PHISH-X extracts the model's five trained features, runs the
                validated Newton Logistic Regression artifact, and explains
                the result. Analysis is local; the destination is never opened.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.container(border=True):
        st.markdown("#### Target URL")
        url_input = st.text_input(
            "URL",
            placeholder="https://example.com/login",
            label_visibility="collapsed",
            key="phishx_url_input",
        )
        analyze = st.button(
            "◈  ANALYZE URL",
            width="stretch",
            type="primary",
        )

    if analyze:
        if not url_input.strip():
            st.warning("Enter a URL first.")
        elif not MODEL_ARTIFACT_PATH.is_file():
            st.error("The trained PHISH-X model artifact was not found.")
            st.code(str(MODEL_ARTIFACT_PATH), language="text")
            st.markdown(
                "Place the trusted `phishx_newton_model.joblib` file at the "
                "path above, or set the `PHISHX_MODEL_ARTIFACT` environment "
                "variable to its location. The artifact is intentionally not "
                "committed to GitHub."
            )
        else:
            try:
                with st.spinner("Loading the trained model and analyzing the URL..."):
                    artifact = load_phishx_model(str(MODEL_ARTIFACT_PATH))
                    from phishx.inference import predict_url

                    result = predict_url(url_input, artifact)
            except FileNotFoundError:
                st.error("The model artifact disappeared or could not be found. Check its configured path.")
            except (ValueError, TypeError) as exc:
                st.error(f"PHISH-X could not analyze this URL: {exc}")
            except Exception:
                st.error(
                    "PHISH-X encountered an unexpected inference error. "
                    "Check the application logs and verify the model artifact and dependencies."
                )
            else:
                st.markdown("<br>", unsafe_allow_html=True)
                st.markdown(
                    f"""
                    <div class="url-result">
                        <div class="url-result-title">TARGET UNDER INVESTIGATION</div>
                        <div class="url-result-value">{html.escape(result.url)}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                st.markdown("<br>", unsafe_allow_html=True)
                section_title("MODEL PREDICTION")

                if result.prediction == "Phishing":
                    st.error("PHISHING DETECTED — treat this URL as suspicious.")
                else:
                    st.success("MODEL CLASSIFICATION: LEGITIMATE")

                probability_cols = st.columns(2)
                with probability_cols[0]:
                    st.metric(
                        "Phishing probability",
                        f"{result.phishing_probability:.2%}",
                    )
                with probability_cols[1]:
                    st.metric(
                        "Legitimate probability",
                        f"{result.legitimate_probability:.2%}",
                    )

                st.caption(
                    f"Decision threshold: {result.threshold:.2%}. "
                    "Probabilities are model estimates, not proof that a destination is safe."
                )

                st.markdown("<br>", unsafe_allow_html=True)
                section_title("EXPLAINABLE MODEL FEATURES")

                contribution_rows = []
                for feature_name, raw_value in result.model_features.items():
                    contribution = result.contributions[feature_name]
                    contribution_rows.append(
                        {
                            "Feature": feature_name,
                            "Extracted value": raw_value,
                            "Logit contribution": contribution,
                            "Direction": (
                                "Toward Legitimate"
                                if contribution >= 0
                                else "Toward Phishing"
                            ),
                        }
                    )

                contribution_df = pd.DataFrame(contribution_rows)
                left, right = st.columns([1.15, 1])

                with left:
                    st.markdown("#### Feature contribution to model logit")
                    max_abs_contribution = max(
                        (abs(float(value)) for value in contribution_df["Logit contribution"]),
                        default=0.0,
                    ) or 1.0
                    chart_rows = []
                    for row in contribution_df.sort_values(
                        "Logit contribution",
                        key=lambda values: values.abs(),
                        ascending=False,
                    ).itertuples(index=False):
                        value = float(row[2])
                        width = abs(value) / max_abs_contribution * 48.0
                        is_positive = value >= 0
                        bar_color = GREEN if is_positive else RED
                        bar_style = (
                            f"left:50%;width:{width:.2f}%;"
                            if is_positive
                            else f"right:50%;width:{width:.2f}%;"
                        )
                        chart_rows.append(
                            f"""
                            <div style="display:grid;grid-template-columns:minmax(115px,1fr) 2fr 92px;
                                        align-items:center;gap:10px;margin:13px 0;">
                                <div style="color:#C7D5E5;font-size:0.78rem;overflow-wrap:anywhere;">
                                    {html.escape(str(row[0]))}
                                </div>
                                <div style="position:relative;height:22px;background:#142235;
                                            border-radius:5px;overflow:hidden;">
                                    <div style="position:absolute;left:50%;top:0;bottom:0;
                                                width:1px;background:#71849B;"></div>
                                    <div style="position:absolute;top:4px;bottom:4px;
                                                {bar_style}background:{bar_color};border-radius:3px;"></div>
                                </div>
                                <div style="font-family:'Space Mono',monospace;color:{bar_color};
                                            font-size:0.72rem;text-align:right;">
                                    {value:+.6f}
                                </div>
                            </div>
                            """
                        )
                    st.html(
                        """
                        <div style="display:flex;justify-content:space-between;
                                    color:#8192A8;font-size:0.68rem;margin:0 100px 4px 0;">
                            <span>← Toward Phishing</span><span>Toward Legitimate →</span>
                        </div>
                        """
                        + "".join(chart_rows)
                    )

                with right:
                    st.markdown("#### Numerical breakdown")
                    display_df = contribution_df[
                        ["Feature", "Extracted value", "Logit contribution"]
                    ].copy()
                    display_df["Extracted value"] = display_df["Extracted value"].map(
                        lambda value: f"{value:.6g}"
                    )
                    display_df["Logit contribution"] = display_df[
                        "Logit contribution"
                    ].map(lambda value: f"{value:+.6f}")
                    st.table(display_df)
                    st.metric("Model bias", f"{result.bias_contribution:+.6f}")
                    st.metric("Final model logit", f"{result.logit:+.6f}")

                st.caption(
                    "Positive contributions move the logit toward Legitimate (class 1); "
                    "negative contributions move it toward Phishing (class 0). "
                    "These are additive log-odds contributions, not causal explanations."
                )

                st.markdown("<br>", unsafe_allow_html=True)
                section_title("INDEPENDENT SECURITY ASSESSMENT")

                assessment = result.security_assessment
                assessment_cols = st.columns(2)
                with assessment_cols[0]:
                    st.metric(
                        "Structural assessment",
                        assessment.get("status", "unavailable").replace("_", " ").title(),
                    )
                with assessment_cols[1]:
                    st.metric(
                        "Rule-based severity",
                        assessment.get("risk_level", "none").upper(),
                    )

                actual_host = assessment.get("actual_host")
                if actual_host:
                    st.write(f"**Actual destination host:** `{actual_host}`")

                findings = assessment.get("findings", [])
                if findings:
                    for finding in findings:
                        severity = finding.get("severity", "medium").lower()
                        message = (
                            f"**{finding.get('title', 'Security finding')}** — "
                            f"{finding.get('description', '')}"
                        )
                        if severity == "high":
                            st.error(message)
                        else:
                            st.warning(message)
                else:
                    st.success("No structural red flags were detected by the current rule set.")

                st.caption(
                    assessment.get(
                        "note",
                        "Structural checks are advisory and do not guarantee safety.",
                    )
                )
                st.info(
                    "The security assessment is deliberately separate from the AI model. "
                    "It does not rewrite the prediction or either probability."
                )

                if result.extraction_warnings:
                    with st.expander("Feature extraction warnings"):
                        for warning in result.extraction_warnings:
                            st.warning(warning)

                with st.expander("Technical URL security signals"):
                    visible_signals = {
                        name: value
                        for name, value in result.security_signals.items()
                        if value not in (False, None, 0, "", [], {})
                    }
                    if visible_signals:
                        signals_df = pd.DataFrame(
                            list(visible_signals.items()),
                            columns=["Signal", "Value"],
                        )
                        st.dataframe(
                            signals_df,
                            width="stretch",
                            hide_index=True,
                        )
                    else:
                        st.caption("No non-default parser signals were returned.")

    st.markdown("<br>", unsafe_allow_html=True)

    with st.expander("How PHISH-X analyzes a URL"):
        st.markdown(
            """
            1. Validate and load the trusted Newton Logistic Regression artifact.
            2. Reuse the project's canonical URL feature extractor.
            3. Select the exact five model features and apply the fitted scaler.
            4. Calculate the phishing and legitimate probabilities.
            5. Explain the model logit using additive feature contributions.
            6. Run independent structural security rules without changing the ML result.

            The URL is parsed locally. PHISH-X does not visit the URL, perform DNS
            lookups, or contact the destination website.
            """
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">
        PHISH-X &nbsp;•&nbsp; EXPLAINABLE AI-BASED PHISHING URL ANALYSIS
        <br><br>
        NUMERICAL COMPUTATIONS &nbsp; / &nbsp; CYBERSECURITY &nbsp; / &nbsp; MACHINE LEARNING
    </div>
    """,
    unsafe_allow_html=True,
)
