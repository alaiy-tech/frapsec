"""One synthetic positive + negative case per vendored security semgrep
rule. Runs semgrep for real (skips with a message if not on PATH -- same
convention as the rest of frapsec's optional layers). Exists because the
frapsec-* id rename silently broke the runner's _SKIP list undetected until
manually checked -- this is the regression guard that should have caught it.
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RULES_DIR = str(Path(__file__).parent.parent / "frapsec" / "semgrep_rules")

# rule_id -> (positive file content, negative file content, filename)
CASES = {
    "frapsec-relaxed-permissions": (
        '{"doctype": "DocType", "permissions": [{"role": "All", "read": 1}]}',
        '{"doctype": "DocType", "permissions": [{"role": "System Manager", "read": 1}]}',
        "perm.json",
    ),
    "frapsec-setuser": (
        'import frappe\ndef job():\n    frappe.set_user("Administrator")\n',
        'import frappe\ndef job(u):\n    pass\n',
        "setuser.py",
    ),
    "frapsec-realtime-pick-room": (
        'import frappe\ndef notify():\n    frappe.publish_realtime("evt", {"x": 1})\n',
        'import frappe\ndef notify():\n    frappe.publish_realtime("evt", {"x": 1}, room="r1")\n',
        "realtime.py",
    ),
    "frapsec-monkey-patching-not-allowed": (
        'from frappe import utils\nutils.some_prop = 1\n',
        'import frappe\nx = 1\n',
        "monkeypatch.py",
    ),
    "frapsec-security-file-traversal": (
        'def read(p):\n    return open(p).read()\n',
        'def noop():\n    return 1\n',
        "traversal.py",
    ),
    "frapsec-format-string-injection": (
        'from frappe import _\ndef h():\n    try:\n        pass\n'
        '    except Exception as e:\n        frappe.throw(_("Error: {0}").format(e))\n',
        'from frappe import _\ndef h():\n    try:\n        pass\n'
        '    except Exception as e:\n        frappe.throw(_("Error: {0}").format(str(e)))\n',
        "fmtstr.py",
    ),
    "frapsec-codeinjection-eval": (
        'def run(x):\n    return eval(x)\n',
        'def run(x):\n    return int(x)\n',
        "eval.py",
    ),
    "frapsec-ssti": (
        'import frappe\ndef render(t):\n    return frappe.render_template(t, {})\n',
        'import frappe\ndef render(t):\n    return t\n',
        "ssti.py",
    ),
    "frapsec-sql-format-injection": (
        'import frappe\ndef q(name):\n    return frappe.db.sql(f"SELECT * FROM tabX WHERE name={name}")\n',
        'import frappe\ndef q(name):\n    return frappe.db.sql("SELECT * FROM tabX WHERE name=%s", (name,))\n',
        "sqlinj.py",
    ),
    "frapsec-breaks-multitenancy": (
        'import frappe\nGLOBAL_DOC = frappe.get_doc("X", "Y")\n',
        'import frappe\ndef get():\n    return frappe.get_doc("X", "Y")\n',
        "multitenancy.py",
    ),
    "frapsec-cache-breaks-multitenancy": (
        'import frappe\ndef set_it():\n    frappe.cache().set("k", "v")\n',
        'import frappe\ndef set_it():\n    frappe.db.set_value("X", "n", "f", "v")\n',
        "cache.py",
    ),
    "frapsec-manual-commit": (
        'import frappe\ndef save():\n    frappe.db.commit()\n',
        'import frappe\ndef save():\n    try:\n        frappe.db.commit()\n'
        '    except Exception:\n        pass\n',
        "commit.py",
    ),
    "frapsec-redis-flush": (
        'import frappe\ndef clear():\n    frappe.cache().flushall()\n',
        'import frappe\ndef clear():\n    frappe.cache().flushdb()\n',
        "flush.py",
    ),
    "frapsec-overriding-local-proxies": (
        "import frappe\nbackup = frappe.db\nfrappe.db = backup\n",
        "import frappe\nfrappe.custom_attr = 1\n",
        "proxies.py",
    ),
}

# test-whitelist-missing-protection needs a real doctype-test path layout,
# handled separately below rather than forced into the flat CASES shape.
_WHITELIST_POS = 'import frappe\n@frappe.whitelist()\ndef run_test():\n    pass\n'
_WHITELIST_NEG = 'import frappe\n@frappe.whitelist_for_tests()\ndef run_test():\n    pass\n'


def _run_semgrep(target: str) -> list[dict]:
    proc = subprocess.run(
        ["semgrep", "scan", "--config", RULES_DIR, "--json", "--quiet", target],
        capture_output=True, text=True,
    )
    return json.loads(proc.stdout).get("results", [])


def test():
    if not shutil.which("semgrep"):
        print("SKIP (semgrep not on PATH)")
        return

    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        pos_dir, neg_dir = tmp / "pos", tmp / "neg"
        pos_dir.mkdir()
        neg_dir.mkdir()
        for rule_id, (pos_src, neg_src, fname) in CASES.items():
            (pos_dir / f"{rule_id}_{fname}").write_text(pos_src)
            (neg_dir / f"{rule_id}_{fname}").write_text(neg_src)

        doctype_dir = tmp / "myapp" / "doctype" / "thing"
        doctype_dir.mkdir(parents=True)
        (doctype_dir / "test_thing.py").write_text(_WHITELIST_POS)
        (doctype_dir / "test_thing_neg.py").write_text(_WHITELIST_NEG)

        pos_results = _run_semgrep(str(tmp))
        hit_ids = {r["check_id"].rsplit(".", 1)[-1] for r in pos_results}

        failures = []
        for rule_id in CASES:
            # positive file should trigger; negative file (same rule_id in
            # its name) should not appear associated with a neg/ path hit
            pos_hits = [r for r in pos_results if r["check_id"].rsplit(".", 1)[-1] == rule_id
                        and "\\pos\\" in r["path"] or (r["check_id"].rsplit(".", 1)[-1] == rule_id and "/pos/" in r["path"])]
            neg_hits = [r for r in pos_results if r["check_id"].rsplit(".", 1)[-1] == rule_id
                        and ("\\neg\\" in r["path"] or "/neg/" in r["path"])]
            if not pos_hits:
                failures.append(f"{rule_id}: positive case did NOT fire")
            if neg_hits:
                failures.append(f"{rule_id}: negative case fired ({neg_hits[0]['path']})")

        if "frapsec-test-whitelist-missing-protection" not in hit_ids:
            failures.append("frapsec-test-whitelist-missing-protection: positive case did NOT fire")
        whitelist_neg_hits = [r for r in pos_results
                               if r["check_id"].rsplit(".", 1)[-1] == "frapsec-test-whitelist-missing-protection"
                               and "test_thing_neg" in r["path"]]
        if whitelist_neg_hits:
            failures.append("frapsec-test-whitelist-missing-protection: negative case fired")

        if failures:
            raise AssertionError("\n" + "\n".join(failures))

    print(f"OK ({len(CASES) + 1} rules verified)")


if __name__ == "__main__":
    test()
