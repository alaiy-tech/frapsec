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


@dataclass
class DocType:
    app: str
    name: str
    file: str
    is_child: bool = False
    permissions: list[dict] = field(default_factory=list)  # raw perm rows from JSON


@dataclass
class App:
    name: str
    path: str
    hooks: dict = field(default_factory=dict)      # parsed hooks.py values
    doctypes: list[DocType] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)


@dataclass
class Finding:
    rule_id: str
    severity: str        # critical | high | medium | low | info
    message: str
    file: str
    line: int = 1
    app: str = ""
