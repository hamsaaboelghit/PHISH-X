
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
