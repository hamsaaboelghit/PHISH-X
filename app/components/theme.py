import streamlit as st

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


def apply_theme():
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
