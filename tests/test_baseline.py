import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from frapsec import baseline  # noqa: E402
from frapsec.model import Finding  # noqa: E402


def test():
    f1 = Finding(rule_id="FRAP-BIZ-002", severity="medium", message="m",
                 file=str(Path(__file__)), line=1)
    f2 = Finding(rule_id="FRAP-BIZ-002", severity="medium", message="m",
                 file=str(Path(__file__)), line=2)

    path = str(Path(__file__).parent / "_tmp_baseline.json")
    try:
        n = baseline.save(path, [f1])
        assert n == 1
        accepted = baseline.load(path)
        assert len(baseline.filter_new([f1, f2], accepted)) == 1, "f1 filtered, f2 remains"
        assert baseline.filter_new([f1], accepted) == [], "accepted finding fully suppressed"
    finally:
        Path(path).unlink(missing_ok=True)


def test_same_basename_different_dirs_do_not_collide():
    """Two files with the same NAME and the same flagged line are two findings.

    Keying on the basename alone made api/orders.py and shopify/orders.py the
    same entry, so accepting the first silently suppressed the second -- a real
    finding hidden by a baseline nobody asked to hide it.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for sub in ("api", "shopify"):
            (root / "myapp" / sub).mkdir(parents=True)
            (root / "myapp" / sub / "orders.py").write_text(
                "frappe.db.delete('Thing')\n", encoding="utf-8")

        a = Finding(rule_id="FRAP-DB-001", severity="high", app="myapp",
                    message="x", file=str(root / "myapp" / "api" / "orders.py"), line=1)
        b = Finding(rule_id="FRAP-DB-001", severity="high", app="myapp",
                    message="x", file=str(root / "myapp" / "shopify" / "orders.py"), line=1)

        bl = str(root / "bl.json")
        assert baseline.save(bl, [a]) == 1
        accepted = baseline.load(bl)
        assert baseline.filter_new([a], accepted) == [], "a was accepted"
        assert baseline.filter_new([b], accepted) == [b], "same basename must not collide"


def test_baseline_is_readable_not_just_hashes():
    """An accepted finding has to be auditable, or nobody can argue with it."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "myapp").mkdir()
        src = root / "myapp" / "code.py"
        src.write_text("frappe.db.delete('Thing')\n", encoding="utf-8")
        f = Finding(rule_id="FRAP-DB-001", severity="high", app="myapp",
                    message="deletes every row of Thing", file=str(src), line=1)

        bl = str(root / "bl.json")
        baseline.save(bl, [f])
        data = json.loads(Path(bl).read_text())
        entry = data["accepted"][0]
        assert entry["rule_id"] == "FRAP-DB-001", entry
        assert entry["severity"] == "high", entry
        assert "code.py" in entry["file"], entry
        assert entry["summary"], "an accepted finding must record WHAT was accepted"


def test_v1_baseline_still_loads():
    """An existing v1 file (a bare list of hashes) must not break the tool."""
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "old.json"
        p.write_text(json.dumps({"accepted": ["abc123", "def456"]}), encoding="utf-8")
        assert baseline.load(str(p)) == {"abc123", "def456"}


if __name__ == "__main__":
    test()
    test_same_basename_different_dirs_do_not_collide()
    test_baseline_is_readable_not_just_hashes()
    test_v1_baseline_still_loads()
    print("OK (4 cases)")
