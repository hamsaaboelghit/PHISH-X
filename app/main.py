
from pathlib import Path
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

from components.theme import (
    apply_theme,
    BG,
    PANEL,
    PANEL_2,
    BORDER,
    CYAN,
    BLUE,
    PURPLE,
    GREEN,
    RED,
    MUTED,
    WHITE,
)

from components.charts import style_chart

from components.cards import (
    section_title,
    page_header,
    metric_card,
)

from utils.url_helpers import (
    safe_hostname,
    extract_basic_signals,
)


# ============================================================
# PHISH-X | THREAT INTELLIGENCE PLATFORM
# ============================================================

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "data" / "raw" / "url_features_extracted1.csv"

st.set_page_config(
    page_title="PHISH-X | Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

apply_theme()


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

            st.plotly_chart(fig, use_container_width=True)

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

        st.plotly_chart(fig, use_container_width=True)

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
            st.plotly_chart(fig, use_container_width=True)

            stats = plot_df.groupby("Class")[selected_feature].agg(
                ["count", "mean", "median", "std", "min", "max"]
            )

            st.dataframe(
                stats.style.format("{:.3f}"),
                use_container_width=True,
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

            st.plotly_chart(fig, use_container_width=True)

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
            st.plotly_chart(fig, use_container_width=True)

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
                st.dataframe(missing_df, use_container_width=True)
            else:
                st.success("No missing values detected.")

        with right:
            st.markdown("**Dataset structure**")

            schema_df = pd.DataFrame({
                "Column": df.columns,
                "Data type": df.dtypes.astype(str).values,
                "Missing": df.isna().sum().values,
            })

            st.dataframe(schema_df, use_container_width=True, height=300)

        st.markdown("<br>", unsafe_allow_html=True)

        if "URL" in df.columns:
            duplicate_rows = df[df["URL"].duplicated(keep=False)].copy()

            if len(duplicate_rows):
                st.markdown("**Duplicate URL samples**")
                st.dataframe(
                    duplicate_rows[["URL", "ClassLabel"]].head(20),
                    use_container_width=True,
                )

        st.warning(
            "Duplicate records and class composition require investigation "
            "before model training. This page does not automatically clean or modify the raw dataset."
        )


# ============================================================
# PAGE 3 — OPTIMIZATION LAB
# ============================================================

elif page == "Optimization Lab":

    page_header(
        "NUMERICAL COMPUTATIONS / OPTIMIZATION",
        "Numerical Optimization Lab",
        "The mathematical workspace behind PHISH-X model training.",
    )

    st.markdown(
        """
        <div class="hero">
            <div class="hero-kicker">NUMERICAL METHODS ENGINE</div>
            <div class="hero-title">Optimization is where mathematics meets intelligence.</div>
            <div class="hero-text">
                PHISH-X is designed to compare numerical approaches for
                optimizing Logistic Regression parameters using a
                Binary Cross-Entropy objective.
            </div>
            <span class="hero-tag">GRADIENT DESCENT</span>
            <span class="hero-tag">NEWTON METHOD</span>
            <span class="hero-tag">LOGISTIC REGRESSION</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Optimization methods")

    col1, col2 = st.columns(2, gap="large")

    with col1:
        with st.container(border=True):
            st.markdown("#### Gradient Descent")
            st.latex(r"W_{new}=W-\alpha\nabla J(W)")
            st.markdown(
                """
                **Core idea**

                Iteratively update model parameters in the opposite
                direction of the gradient.

                **What we will measure**
                - Convergence behavior
                - Number of iterations
                - Final objective value
                - Runtime
                """
            )

    with col2:
        with st.container(border=True):
            st.markdown("#### Newton's Method")
            st.latex(r"W_{new}=W-H^{-1}\nabla J(W)")
            st.markdown(
                """
                **Core idea**

                Use first and second derivatives to estimate a
                better parameter update.

                **What we will measure**
                - Convergence behavior
                - Number of iterations
                - Final objective value
                - Computational cost
                """
            )

    st.markdown("<br>", unsafe_allow_html=True)

    with st.container(border=True):
        st.markdown("### Objective function")

        st.latex(
            r"J(W)=-\frac{1}{m}\sum_{i=1}^{m}"
            r"\left[y_i\log(p_i)+(1-y_i)\log(1-p_i)\right]"
        )

        st.markdown(
            """
            Where:

            - \(m\): number of training examples
            - \(y_i\): actual class label
            - \(p_i\): predicted probability
            - \(W\): model parameter vector

            The optimization experiment will compare how each
            numerical method minimizes this objective.
            """
        )

    st.info(
        "Optimization experiments are not connected yet. "
        "No training results, convergence curves or performance comparisons are fabricated here."
    )


# ============================================================
# PAGE 4 — URL INVESTIGATION
# ============================================================

elif page == "URL Investigation":

    page_header(
        "SECURITY OPERATIONS / URL ANALYSIS",
        "URL Investigation",
        "Inspect URL structure and extract preliminary security-relevant signals.",
    )

    st.markdown(
        """
        <div class="hero">
            <div class="hero-kicker">ANALYST WORKSPACE / MANUAL INSPECTION</div>
            <div class="hero-title">Investigate a suspicious URL.</div>
            <div class="hero-text">
                Enter a URL to inspect its structure and extract
                preliminary characteristics. The URL is parsed locally;
                this tool does not visit or open the destination.
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
        )

        analyze = st.button(
            "◈  ANALYZE URL",
            use_container_width=True,
        )

    if analyze:

        if not url_input.strip():
            st.warning("Enter a URL first.")

        else:
            signals = extract_basic_signals(url_input)

            if not signals:
                st.error("Could not parse this URL.")
            else:
                st.markdown("<br>", unsafe_allow_html=True)

                st.markdown(
                    f"""
                    <div class="url-result">
                        <div class="url-result-title">TARGET UNDER INVESTIGATION</div>
                        <div class="url-result-value">{html.escape(url_input)}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                st.markdown("<br>", unsafe_allow_html=True)
                section_title("EXTRACTED URL SIGNALS")

                cols = st.columns(3)

                for i, (name, value) in enumerate(signals.items()):
                    with cols[i % 3]:
                        st.metric(name, f"{value:,}")

                st.markdown("<br>", unsafe_allow_html=True)

                with st.container(border=True):
                    st.markdown("#### Signal details")

                    signal_df = pd.DataFrame(
                        list(signals.items()),
                        columns=["Feature", "Extracted value"],
                    )

                    st.dataframe(
                        signal_df,
                        use_container_width=True,
                        hide_index=True,
                    )

                st.info(
                    "These are preliminary structural signals only. "
                    "They are not a phishing classification or a trained-model prediction."
                )

    st.markdown("<br>", unsafe_allow_html=True)

    with st.expander("How URL analysis works"):
        st.markdown(
            """
            1. Normalize the input enough to parse its URL structure.
            2. Extract the hostname, path and query string.
            3. Calculate basic numerical URL characteristics.
            4. Display the extracted signals for analyst inspection.

            No external URL is opened or contacted.
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
