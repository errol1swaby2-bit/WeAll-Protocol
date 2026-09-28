from pathlib import Path

SOURCE_COMMIT = "f9a283eff272db5fe236482895ad3e205553d05b"
WORKFLOW_PATH = ".github/workflows/p2b-materialized-helper-local-plan-binding-closure.yml"


def main() -> None:
    import subprocess

    text = subprocess.check_output(
        ["git", "show", f"{SOURCE_COMMIT}:{WORKFLOW_PATH}"],
        text=True,
    )
    marker = "          python - <<'PY'\n"
    start = text.index(marker) + len(marker)
    end = text.index("\n          PY\n", start)
    block = text[start:end]

    lines: list[str] = []
    in_raw = False
    for original in block.splitlines():
        if in_raw:
            lines.append(original)
            if original.strip() == "'''":
                in_raw = False
            continue
        line = original[10:] if original.startswith("          ") else original
        lines.append(line)
        if "= r'''" in line:
            in_raw = True

    patcher = "\n".join(lines) + "\n"
    compile(patcher, "/tmp/p2b_patch.py", "exec")
    Path("/tmp/p2b_patch.py").write_text(patcher, encoding="utf-8")


if __name__ == "__main__":
    main()
