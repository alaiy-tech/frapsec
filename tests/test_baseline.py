import sys
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
        assert len(baseline.filter_new([f1, f2], accepted)) == 1, "f1 should be filtered, f2 should remain"
        assert baseline.filter_new([f1], accepted) == [], "accepted finding should be fully suppressed"
    finally:
        Path(path).unlink(missing_ok=True)
    print("OK")


if __name__ == "__main__":
    test()
