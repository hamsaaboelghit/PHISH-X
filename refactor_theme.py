
import ast
from pathlib import Path
import textwrap

ROOT = Path(__file__).resolve().parent
MAIN = ROOT / "app" / "main.py"
COMPONENTS = ROOT / "app" / "components"
THEME = COMPONENTS / "theme.py"

source = MAIN.read_text(encoding="utf-8")
tree = ast.parse(source)

theme_names = {
    "BG", "PANEL", "PANEL_2", "BORDER",
    "CYAN", "BLUE", "PURPLE", "GREEN",
    "RED", "MUTED", "WHITE",
}

assignments = []
css_node = None
page_config_node = None

for node in tree.body:
    if isinstance(node, ast.Assign):
        names = {
            target.id
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        if names and names.issubset(theme_names):
            assignments.append(node)

    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        call = node.value
        if (
            isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "st"
            and call.func.attr == "markdown"
            and call.args
            and isinstance(call.args[0], ast.Constant)
            and isinstance(call.args[0].value, str)
            and "<style>" in call.args[0].value
        ):
            css_node = node

    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        call = node.value
        if (
            isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "st"
            and call.func.attr == "set_page_config"
        ):
            page_config_node = node

if not assignments or css_node is None or page_config_node is None:
    raise RuntimeError(
        "Could not identify the theme, CSS, or page configuration."
    )

if THEME.exists():
    raise FileExistsError(
        f"{THEME} already exists. Refusing to overwrite it."
    )

lines = source.splitlines(keepends=True)

def source_for(node):
    return "".join(lines[node.lineno - 1:node.end_lineno])

constants_code = "\n".join(
    source_for(node).rstrip()
    for node in assignments
)

css_code = textwrap.indent(source_for(css_node).rstrip(), "    ")

theme_code = (
    "import streamlit as st\n\n"
    f"{constants_code}\n\n\n"
    "def apply_theme():\n"
    f"{css_code}\n"
)

COMPONENTS.mkdir(parents=True, exist_ok=True)
(THEME.parent / "__init__.py").touch(exist_ok=True)
THEME.write_text(theme_code, encoding="utf-8")

# Remove the extracted constants and CSS from main.py.
remove_nodes = assignments + [css_node]
remove_lines = set()

for node in remove_nodes:
    remove_lines.update(range(node.lineno, node.end_lineno + 1))

updated_lines = [
    line
    for number, line in enumerate(lines, start=1)
    if number not in remove_lines
]

updated = "".join(updated_lines)

# Import the new theme module.
updated = updated.replace(
    "import streamlit as st\n",
    "import streamlit as st\n\n"
    "from components.theme import apply_theme\n",
    1,
)

# Add theme application after page configuration.
updated_tree = ast.parse(updated)
config = next(
    node for node in updated_tree.body
    if isinstance(node, ast.Expr)
    and isinstance(node.value, ast.Call)
    and isinstance(node.value.func, ast.Attribute)
    and isinstance(node.value.func.value, ast.Name)
    and node.value.func.value.id == "st"
    and node.value.func.attr == "set_page_config"
)

updated_lines = updated.splitlines(keepends=True)
updated_lines.insert(config.end_lineno, "\napply_theme()\n")
updated = "".join(updated_lines)

MAIN.write_text(updated, encoding="utf-8")

print("Theme extraction completed.")
print(f"Created: {THEME}")
print("Updated: app/main.py")
print("Original CSS and color constants were moved, not rewritten.")
