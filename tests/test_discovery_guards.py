"""discover_app must fail loudly on a path it cannot read.

A scan that finds nothing because it looked in the wrong place is worse than an
error: it reports "No findings" with exit code 0, which reads as a clean bill of
health. Confirmed live -- a mistyped path scanned ten real connector apps and
reported zero findings for every one of them, silently, because discovery
returned an empty App and every rule then had nothing to examine.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from frapsec import discovery  # noqa: E402


def test():
    # A path that does not exist at all.
    try:
        discovery.discover_app("/no/such/directory/anywhere")
    except SystemExit as e:
        assert "not a directory" in str(e), e
    else:
        raise AssertionError("a non-existent path must raise, not return an empty App")

    # A real directory with no Python in it -- a docs folder, a bench root, a
    # repo whose package lives somewhere else. Scanning it is always a mistake.
    with tempfile.TemporaryDirectory() as tmp:
        empty = Path(tmp) / "notanapp"
        (empty / "docs").mkdir(parents=True)
        (empty / "docs" / "readme.md").write_text("not code", encoding="utf-8")
        try:
            discovery.discover_app(str(empty))
        except SystemExit as e:
            assert "no Python files" in str(e), e
        else:
            raise AssertionError("a directory with no Python must raise")

    # A real app still discovers normally -- the guards must not reject the
    # layout they exist to protect.
    with tempfile.TemporaryDirectory() as tmp:
        app = Path(tmp) / "myapp" / "myapp"
        app.mkdir(parents=True)
        (app / "hooks.py").write_text("app_name = 'myapp'\n", encoding="utf-8")
        (app / "api.py").write_text(
            "import frappe\n\n"
            "@frappe.whitelist()\n"
            "def thing():\n"
            "    return 1\n",
            encoding="utf-8",
        )
        found = discovery.discover_app(str(Path(tmp) / "myapp"))
        assert found.endpoints, "a real app must still yield endpoints"
        assert found.hooks.get("app_name") == "myapp", found.hooks

    # The inner package passed directly is a documented, supported form.
    with tempfile.TemporaryDirectory() as tmp:
        pkg = Path(tmp) / "innerpkg"
        pkg.mkdir(parents=True)
        (pkg / "thing.py").write_text("x = 1\n", encoding="utf-8")
        discovery.discover_app(str(pkg))  # must not raise

    print("OK")


if __name__ == "__main__":
    test()
