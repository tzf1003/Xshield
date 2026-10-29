#!/usr/bin/env python3
"""Self-test for check_audit_event_coverage.py on synthetic control/worker sources.

Proves the gate fails when a new control endpoint emits an audit event the
worker publisher would refuse (missing from `supports()` or from the
(event, method, path) matrix, or with a path constant it cannot resolve), and
passes once the publisher lists it. Run: python3 scripts/test_check_audit_event_coverage.py
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "check_audit_event_coverage.py"
SPEC = importlib.util.spec_from_file_location("check_audit_event_coverage", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)

LIST_ENDPOINT = '''
pub(super) const PATH: &str = "/control/v1/widgets";
pub(super) const ACCESS: AccessAction = AccessAction {
    event_type: "console.widget.list",
    method: "GET",
    path: PATH,
    role: ManagementRole::Observer,
};
'''

# A refusal branch added later: a new endpoint with its own audit event.
DELETE_ENDPOINT = '''
pub(super) const DELETE: AccessAction = AccessAction {
    event_type: "console.widget.delete",
    method: "POST",
    path: "/control/v1/widgets/delete",
    role: ManagementRole::Operator,
};
'''


def worker(events: list[str], matrix: list[tuple[str, str, str]]) -> str:
    supported = "\n            | ".join(f'"{event}"' for event in events) or '"none"'
    arms = "\n            | ".join(f'("{event}", "{method}", "{path}")' for event, method, path in matrix)
    return f'''
pub(super) fn supports(event_type: &str) -> bool {{
    matches!(
        event_type,
        {supported}
    )
}}

impl Payload {{
    fn validate_targets(&self, event_type: &str) -> bool {{
        let allowed = match (event_type, self.method.as_str(), self.path.as_str()) {{
            {arms} => true,
            _ => false,
        }};
        allowed
    }}
}}
'''


LIST = ("console.widget.list", "GET", "/control/v1/widgets")
DELETE = ("console.widget.delete", "POST", "/control/v1/widgets/delete")


class CoverageGate(unittest.TestCase):
    def run_gate(self, control: dict[str, str], worker_source: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            control_dir = root / "control"
            for name, text in control.items():
                path = control_dir / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            worker_path = root / "control_audit.rs"
            worker_path.write_text(worker_source, encoding="utf-8")
            stderr, stdout = io.StringIO(), io.StringIO()
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                status = checker.main(control_dir, worker_path)
            return status, stderr.getvalue() + stdout.getvalue()

    def test_publishable_endpoints_pass(self) -> None:
        status, output = self.run_gate(
            {"widgets.rs": LIST_ENDPOINT + DELETE_ENDPOINT},
            worker([LIST[0], DELETE[0]], [LIST, DELETE]),
        )
        self.assertEqual(status, 0, output)
        self.assertIn("ok: 2 control audit events", output)

    def test_new_event_missing_from_supports_fails(self) -> None:
        status, output = self.run_gate(
            {"widgets.rs": LIST_ENDPOINT + DELETE_ENDPOINT},
            worker([LIST[0]], [LIST, DELETE]),
        )
        self.assertEqual(status, 1)
        self.assertIn("NOT IN supports(): console.widget.delete", output)

    def test_new_event_missing_from_matrix_fails(self) -> None:
        status, output = self.run_gate(
            {"widgets.rs": LIST_ENDPOINT + DELETE_ENDPOINT},
            worker([LIST[0], DELETE[0]], [LIST]),
        )
        self.assertEqual(status, 1)
        self.assertIn("NOT PUBLISHABLE: console.widget.delete POST /control/v1/widgets/delete", output)

    def test_wrong_method_or_path_is_not_publishable(self) -> None:
        status, output = self.run_gate(
            {"widgets.rs": LIST_ENDPOINT},
            worker([LIST[0]], [("console.widget.list", "POST", "/control/v1/widgets")]),
        )
        self.assertEqual(status, 1)
        self.assertIn("NOT PUBLISHABLE: console.widget.list GET /control/v1/widgets", output)

    def test_unresolved_path_constant_fails_closed(self) -> None:
        source = LIST_ENDPOINT.replace("path: PATH,", "path: elsewhere::MISSING,")
        status, output = self.run_gate({"widgets.rs": source}, worker([LIST[0]], [LIST]))
        self.assertEqual(status, 1)
        self.assertIn("UNRESOLVED path constant", output)

    def test_qualified_constant_resolves_from_its_module(self) -> None:
        source = LIST_ENDPOINT.replace('pub(super) const PATH: &str = "/control/v1/widgets";\n', "")
        source = source.replace("path: PATH,", "path: routes::PATH,")
        status, output = self.run_gate(
            {"widgets.rs": source, "routes.rs": 'pub const PATH: &str = "/control/v1/widgets";\n'},
            worker([LIST[0]], [LIST]),
        )
        self.assertEqual(status, 0, output)

    def test_test_modules_are_not_endpoints(self) -> None:
        status, output = self.run_gate(
            {"widgets.rs": LIST_ENDPOINT, "tests/fixture.rs": DELETE_ENDPOINT},
            worker([LIST[0]], [LIST]),
        )
        self.assertEqual(status, 0, output)

    def test_real_repository_is_covered(self) -> None:
        stderr, stdout = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            status = checker.main()
        self.assertEqual(status, 0, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
