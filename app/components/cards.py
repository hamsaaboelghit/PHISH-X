
import streamlit as st


def section_title(title, subtitle=None):
    st.markdown(
        f'<div class="section-label">{title}</div>',
        unsafe_allow_html=True,
    )
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
