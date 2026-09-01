"""Core data model — what discovery produces, what rules consume."""
from dataclasses import dataclass, field


@dataclass
class Endpoint:
    """A @frappe.whitelist() method."""
    app: str
    module: str          # dotted path, e.g. myapp.api.orders
    name: str            # function name
    file: str
    line: int
    allow_guest: bool = False
    methods: list[str] = field(default_factory=list)
    args: list[str] = field(default_factory=list)


@dataclass
class DocType:
    app: str
    name: str
    file: str
    is_child: bool = False
    permissions: list[dict] = field(default_factory=list)  # raw perm rows from JSON
    fieldnames: list[str] = field(default_factory=list)     # fieldname of each field row
    password_fields: list[str] = field(default_factory=list)  # Password-fieldtype fields at permlevel 0
    fields: list[dict] = field(default_factory=list)          # raw field rows (fieldtype, permlevel, ...)


@dataclass
class App:
    name: str
    path: str
    hooks: dict = field(default_factory=dict)      # parsed hooks.py values
    doctypes: list[DocType] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)


@dataclass
class Site:
    name: str
    file: str            # site_config.json path
    config: dict = field(default_factory=dict)   # merged: common_site_config + site_config


@dataclass
class Finding:
    rule_id: str
    severity: str        # critical | high | medium | low | info
    message: str
    file: str
    line: int = 1
    app: str = ""
    endpoint: str = ""    # dotted "module.function" -- set only by API rules;
                          # lets `frapsec verify` call the real endpoint later
    verified: str = ""    # "" until `frapsec verify` runs; then reachable | blocked | error
