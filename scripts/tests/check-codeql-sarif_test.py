#!/usr/bin/env python3

from __future__ import annotations

import copy
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "check-codeql-sarif.py"
SPEC = importlib.util.spec_from_file_location("check_codeql_sarif", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
policy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = policy
SPEC.loader.exec_module(policy)


def rule(
    identifier: str,
    severity: str | None,
    *,
    security_tag: bool = True,
    kind: str | None = None,
    include_help: bool = True,
) -> dict:
    tags = ["security", "external/cwe/cwe-020"] if security_tag else ["summary", "telemetry"]
    rule_kind = kind or ("path-problem" if security_tag else "metric")
    properties: dict[str, object] = {
        "kind": rule_kind,
        "precision": "high",
        "problem.severity": "error" if security_tag else "warning",
        "tags": tags,
    }
    if severity is not None:
        properties["security-severity"] = severity
    descriptor = {
        "id": identifier,
        "name": identifier,
        "shortDescription": {"text": f"Short description for {identifier}"},
        "fullDescription": {"text": f"Full description for {identifier}"},
        "defaultConfiguration": (
            {"level": "error" if security_tag else "warning"}
            if rule_kind != "metric"
            else {"enabled": True}
        ),
        "properties": properties,
    }
    if include_help:
        descriptor["help"] = {
            "text": f"Query help for {identifier}",
            "markdown": f"# Query help for `{identifier}`",
        }
    return descriptor


def result(
    identifier: str,
    rule_index: int,
    *,
    component_index: int | None = 0,
    include_top_level_rule_index: bool = False,
) -> dict:
    reference: dict[str, object] = {"id": identifier, "index": rule_index}
    if component_index is not None:
        reference["toolComponent"] = {"index": component_index, "name": "codeql/go-queries"}
    finding = {
        "ruleId": identifier,
        "rule": reference,
        "level": "error",
        "kind": "fail",
        "message": {"text": f"Finding for {identifier}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": "pkg/service.go",
                        "uriBaseId": "%SRCROOT%",
                        "index": 0,
                    },
                    "region": {"startLine": 10, "startColumn": 2, "endColumn": 8},
                }
            }
        ],
        "partialFingerprints": {"primaryLocationLineHash": f"fingerprint-{identifier}"},
    }
    if include_top_level_rule_index:
        finding["ruleIndex"] = rule_index
    return finding


def sarif_document() -> dict:
    rules = [
        rule("go/low-security", "6.9"),
        rule("go/summary/lines-of-code", None, security_tag=False, include_help=False),
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "organization": "GitHub",
                            "semanticVersion": "2.26.3",
                            "rules": [],
                    },
                    "extensions": [
                        {
                            "name": "codeql/go-queries",
                            "guid": "11111111-1111-4111-8111-111111111111",
                            "rules": rules,
                        },
                        {
                            "name": "codeql/go-all",
                            "semanticVersion": "5.5.5",
                        },
                        {
                            "name": "codeql/threat-models",
                            "semanticVersion": "1.0.0",
                        },
                    ],
                },
                "artifacts": [
                    {
                        "location": {
                            "uri": "pkg/service.go",
                            "uriBaseId": "%SRCROOT%",
                            "index": 0,
                        },
                        "sourceLanguage": "go",
                    }
                ],
                "results": [result("go/low-security", 0)],
                "columnKind": "unicodeCodePoints",
                "properties": {
                    "semmle.formatSpecifier": "sarif-latest",
                    "metricResults": [
                        {
                            "rule": {
                                "id": "go/summary/lines-of-code",
                                "index": 1,
                                "toolComponent": {"index": 0},
                            },
                            "ruleId": "go/summary/lines-of-code",
                            "value": 123,
                        }
                    ],
                },
            }
        ],
    }


class SarifPolicyTests(unittest.TestCase):
    def test_real_raw_contract_low_result_and_unreferenced_metric_pass(self):
        self.assertEqual(policy.validate_sarif(sarif_document()), (2, 1))

    def test_ungrouped_driver_rules_refuse(self):
        document = sarif_document()
        run = document["runs"][0]
        driver = run["tool"]["driver"]
        driver["rules"] = run["tool"].pop("extensions")[0]["rules"]
        run["results"] = [
            result("go/low-security", 0, component_index=None),
        ]
        with self.assertRaises(policy.SarifPolicyError):
            policy.validate_sarif(document)

    def test_empty_results_with_complete_rule_metadata_pass(self):
        document = sarif_document()
        document["runs"][0]["results"] = []
        document["runs"][0]["artifacts"] = []
        self.assertEqual(policy.validate_sarif(document), (2, 0))

    def test_optional_matching_top_level_rule_index_and_newline_sequences_pass(self):
        document = sarif_document()
        document["runs"][0]["results"][0]["ruleIndex"] = 0
        document["runs"][0]["newlineSequences"] = ["\r\n", "\n"]
        document["runs"][0]["tool"]["driver"]["version"] = "2.26.3"
        self.assertEqual(policy.validate_sarif(document), (2, 1))

    def test_zero_rule_library_extensions_pass_but_zero_total_rules_refuses(self):
        self.assertEqual(policy.validate_sarif(sarif_document()), (2, 1))
        document = sarif_document()
        document["runs"][0]["tool"]["extensions"][0]["rules"] = []
        document["runs"][0]["results"] = []
        document["runs"][0]["artifacts"] = []
        with self.assertRaises(policy.SarifPolicyError):
            policy.validate_sarif(document)

    def test_high_and_critical_results_refuse_at_inclusive_threshold(self):
        for severity in ("7", "7.0", "8.9", "9.1", "10", "10.0"):
            document = sarif_document()
            document["runs"][0]["tool"]["extensions"][0]["rules"][0]["properties"][
                "security-severity"
            ] = severity
            with self.subTest(severity=severity):
                with self.assertRaises(policy.SarifPolicyError):
                    policy.validate_sarif(document)

    def test_high_result_refuses_even_if_suppressed_or_unchanged(self):
        document = sarif_document()
        document["runs"][0]["tool"]["extensions"][0]["rules"][0]["properties"][
            "security-severity"
        ] = "8.8"
        finding = document["runs"][0]["results"][0]
        finding["suppressions"] = [{"kind": "inSource"}]
        finding["baselineState"] = "unchanged"
        with self.assertRaises(policy.SarifPolicyError):
            policy.validate_sarif(document)

    def test_malformed_or_out_of_range_security_severity_refuses(self):
        malformed = (7, True, "", "0", "0.0", "00.1", "07.0", "+7.0", " 7.0", "7.0 ", "7e0", "nan", "-1", "10.1")
        for severity in malformed:
            document = sarif_document()
            document["runs"][0]["tool"]["extensions"][0]["rules"][0]["properties"][
                "security-severity"
            ] = severity
            with self.subTest(severity=severity):
                with self.assertRaises(policy.SarifPolicyError):
                    policy.validate_sarif(document)

    def test_security_tag_and_severity_must_be_consistent(self):
        missing = sarif_document()
        del missing["runs"][0]["tool"]["extensions"][0]["rules"][0]["properties"]["security-severity"]
        with self.assertRaises(policy.SarifPolicyError):
            policy.validate_sarif(missing)

        untagged = sarif_document()
        untagged["runs"][0]["tool"]["extensions"][0]["rules"][0]["properties"]["tags"] = [
            "maintainability"
        ]
        with self.assertRaises(policy.SarifPolicyError):
            policy.validate_sarif(untagged)

    def test_duplicate_or_malformed_rules_refuse(self):
        mutations = []

        duplicate = sarif_document()
        duplicate_rule = copy.deepcopy(duplicate["runs"][0]["tool"]["extensions"][0]["rules"][0])
        duplicate["runs"][0]["tool"]["extensions"][0]["rules"].append(duplicate_rule)
        mutations.append(duplicate)

        wrong_name = sarif_document()
        wrong_name["runs"][0]["tool"]["extensions"][0]["rules"][0]["name"] = ""
        mutations.append(wrong_name)

        missing_description = sarif_document()
        del missing_description["runs"][0]["tool"]["extensions"][0]["rules"][0]["fullDescription"]
        mutations.append(missing_description)

        missing_help = sarif_document()
        del missing_help["runs"][0]["tool"]["extensions"][0]["rules"][0]["help"]
        mutations.append(missing_help)

        missing_markdown_help = sarif_document()
        del missing_markdown_help["runs"][0]["tool"]["extensions"][0]["rules"][0]["help"]["markdown"]
        mutations.append(missing_markdown_help)

        null_metric_help = sarif_document()
        null_metric_help["runs"][0]["tool"]["extensions"][0]["rules"][1]["help"] = None
        mutations.append(null_metric_help)

        duplicate_tags = sarif_document()
        duplicate_tags["runs"][0]["tool"]["extensions"][0]["rules"][0]["properties"]["tags"] = [
            "security",
            "security",
        ]
        mutations.append(duplicate_tags)

        for index, document in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(policy.SarifPolicyError):
                    policy.validate_sarif(document)

    def test_only_unreferenced_summary_metrics_may_omit_query_help(self):
        nonmetric = sarif_document()
        metric = nonmetric["runs"][0]["tool"]["extensions"][0]["rules"][1]
        metric["properties"]["kind"] = "problem"
        metric["properties"]["tags"] = ["maintainability"]

        unclassified_metric = sarif_document()
        unclassified_metric["runs"][0]["tool"]["extensions"][0]["rules"][1]["properties"][
            "tags"
        ] = ["telemetry"]

        referenced_metric = sarif_document()
        referenced_metric["runs"][0]["results"] = [result("go/summary/lines-of-code", 1)]

        for label, document in (
            ("nonmetric", nonmetric),
            ("unclassified-metric", unclassified_metric),
            ("referenced-metric", referenced_metric),
        ):
            with self.subTest(label=label):
                with self.assertRaises(policy.SarifPolicyError):
                    policy.validate_sarif(document)

    def test_every_alert_result_requires_help_and_security_classification(self):
        missing_security = sarif_document()
        alert = missing_security["runs"][0]["tool"]["extensions"][0]["rules"][0]
        alert["properties"]["tags"] = ["maintainability"]
        del alert["properties"]["security-severity"]

        missing_help = sarif_document()
        del missing_help["runs"][0]["tool"]["extensions"][0]["rules"][0]["help"]

        for label, document in (("missing-security", missing_security), ("missing-help", missing_help)):
            with self.subTest(label=label):
                with self.assertRaises(policy.SarifPolicyError):
                    policy.validate_sarif(document)

    def test_result_rule_id_index_and_component_must_resolve_uniquely(self):
        mutations = []

        wrong_id = sarif_document()
        wrong_id["runs"][0]["results"][0]["ruleId"] = "go/missing"
        wrong_id["runs"][0]["results"][0]["rule"]["id"] = "go/missing"
        mutations.append(wrong_id)

        wrong_rule_index = sarif_document()
        wrong_rule_index["runs"][0]["results"][0]["ruleIndex"] = 1
        mutations.append(wrong_rule_index)

        wrong_reference_index = sarif_document()
        wrong_reference_index["runs"][0]["results"][0]["rule"]["index"] = 1
        mutations.append(wrong_reference_index)

        missing_component = sarif_document()
        missing_component["runs"][0]["results"][0]["rule"]["toolComponent"]["index"] = 1
        mutations.append(missing_component)

        wrong_component_name = sarif_document()
        wrong_component_name["runs"][0]["results"][0]["rule"]["toolComponent"]["name"] = "attacker/pack"
        mutations.append(wrong_component_name)

        missing_rule = sarif_document()
        del missing_rule["runs"][0]["results"][0]["rule"]
        mutations.append(missing_rule)

        missing_reference_id = sarif_document()
        del missing_reference_id["runs"][0]["results"][0]["rule"]["id"]
        mutations.append(missing_reference_id)

        missing_reference_index = sarif_document()
        del missing_reference_index["runs"][0]["results"][0]["rule"]["index"]
        mutations.append(missing_reference_index)

        missing_tool_component = sarif_document()
        del missing_tool_component["runs"][0]["results"][0]["rule"]["toolComponent"]
        mutations.append(missing_tool_component)

        missing_tool_component_index = sarif_document()
        del missing_tool_component_index["runs"][0]["results"][0]["rule"]["toolComponent"]["index"]
        mutations.append(missing_tool_component_index)

        wrong_component_guid = sarif_document()
        wrong_component_guid["runs"][0]["results"][0]["rule"]["toolComponent"]["guid"] = "wrong"
        mutations.append(wrong_component_guid)

        non_integer_rule_index = sarif_document()
        non_integer_rule_index["runs"][0]["results"][0]["ruleIndex"] = True
        mutations.append(non_integer_rule_index)

        for index, document in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(policy.SarifPolicyError):
                    policy.validate_sarif(document)

    def test_ambiguous_rule_id_across_components_refuses(self):
        document = sarif_document()
        duplicate_component = {
            "name": "attacker/duplicate-pack",
            "rules": [copy.deepcopy(document["runs"][0]["tool"]["extensions"][0]["rules"][0])],
        }
        document["runs"][0]["tool"]["extensions"].append(duplicate_component)
        with self.assertRaises(policy.SarifPolicyError):
            policy.validate_sarif(document)

    def test_wrong_schema_run_count_or_tool_identity_refuses(self):
        variants = []
        wrong_schema = sarif_document()
        wrong_schema["$schema"] = "https://attacker.invalid/sarif-schema-2.1.0.json"
        variants.append(wrong_schema)
        wrong_version = sarif_document()
        wrong_version["version"] = "2.0.0"
        variants.append(wrong_version)
        duplicate_run = sarif_document()
        duplicate_run["runs"].append(copy.deepcopy(duplicate_run["runs"][0]))
        variants.append(duplicate_run)
        wrong_driver = sarif_document()
        wrong_driver["runs"][0]["tool"]["driver"]["name"] = "CodeQL command-line toolchain"
        variants.append(wrong_driver)
        wrong_org = sarif_document()
        wrong_org["runs"][0]["tool"]["driver"]["organization"] = "Attacker"
        variants.append(wrong_org)
        wrong_bundle = sarif_document()
        wrong_bundle["runs"][0]["tool"]["driver"]["semanticVersion"] = "2.26.2"
        variants.append(wrong_bundle)
        missing_semantic_version = sarif_document()
        del missing_semantic_version["runs"][0]["tool"]["driver"]["semanticVersion"]
        variants.append(missing_semantic_version)
        disagreeing_optional_version = sarif_document()
        disagreeing_optional_version["runs"][0]["tool"]["driver"]["version"] = "2.26.2"
        variants.append(disagreeing_optional_version)
        null_optional_version = sarif_document()
        null_optional_version["runs"][0]["tool"]["driver"]["version"] = None
        variants.append(null_optional_version)
        wrong_format = sarif_document()
        wrong_format["runs"][0]["properties"]["semmle.formatSpecifier"] = "sarifv2.1.0"
        variants.append(wrong_format)

        for index, document in enumerate(variants):
            with self.subTest(index=index):
                with self.assertRaises(policy.SarifPolicyError):
                    policy.validate_sarif(document)

    def test_column_kind_and_optional_newline_sequences_are_exact(self):
        variants = []
        wrong_column = sarif_document()
        wrong_column["runs"][0]["columnKind"] = "utf16CodeUnits"
        variants.append(wrong_column)
        for newline_value in (None, [], "\n", [""], ["12345"]):
            document = sarif_document()
            document["runs"][0]["newlineSequences"] = newline_value
            variants.append(document)
        for index, document in enumerate(variants):
            with self.subTest(index=index):
                with self.assertRaises(policy.SarifPolicyError):
                    policy.validate_sarif(document)

    def test_external_properties_and_unknown_schema_fields_refuse(self):
        top_external = sarif_document()
        top_external["inlineExternalProperties"] = []
        run_external = sarif_document()
        run_external["runs"][0]["externalPropertyFileReferences"] = {}
        unknown = sarif_document()
        unknown["attacker"] = True
        for document in (top_external, run_external, unknown):
            with self.subTest(document=document):
                with self.assertRaises(policy.SarifPolicyError):
                    policy.validate_sarif(document)

    def test_result_shape_artifact_and_fingerprint_are_required(self):
        mutations = []
        no_message = sarif_document()
        del no_message["runs"][0]["results"][0]["message"]
        mutations.append(no_message)
        no_location = sarif_document()
        no_location["runs"][0]["results"][0]["locations"] = []
        mutations.append(no_location)
        wrong_artifact = sarif_document()
        wrong_artifact["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
            "uri"
        ] = "pkg/other.go"
        mutations.append(wrong_artifact)
        no_fingerprint = sarif_document()
        no_fingerprint["runs"][0]["results"][0]["partialFingerprints"] = {}
        mutations.append(no_fingerprint)
        for index, document in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(policy.SarifPolicyError):
                    policy.validate_sarif(document)

    def test_nonfinite_and_duplicate_json_keys_refuse(self):
        with self.assertRaises(policy.SarifPolicyError):
            policy.parse_json(b'{"version": NaN}')
        duplicate = b'{"version":"2.1.0","version":"2.1.0","runs":[]}'
        with self.assertRaises(policy.SarifPolicyError):
            policy.parse_json(duplicate)


class OutputBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="recasaos-codeql-sarif-test.")
        self.root = pathlib.Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write_document(self, document: dict | None = None, name: str = "go.sarif") -> pathlib.Path:
        target = self.root / name
        target.write_text(json.dumps(document or sarif_document()), encoding="utf-8")
        return target

    def test_exact_regular_go_sarif_file_passes(self):
        self.write_document()
        self.assertEqual(policy.validate_output_directory(str(self.root)), (2, 1))

    def test_relative_directory_refuses(self):
        self.write_document()
        with self.assertRaises(policy.SarifPolicyError):
            policy.validate_output_directory(self.root.name)

    def test_missing_wrong_named_extra_and_nested_entries_refuse(self):
        with self.assertRaises(policy.SarifPolicyError):
            policy.validate_output_directory(str(self.root))

        self.write_document(name="result.sarif")
        with self.assertRaises(policy.SarifPolicyError):
            policy.validate_output_directory(str(self.root))
        (self.root / "result.sarif").unlink()

        self.write_document()
        (self.root / "extra.txt").write_text("extra", encoding="utf-8")
        with self.assertRaises(policy.SarifPolicyError):
            policy.validate_output_directory(str(self.root))
        (self.root / "extra.txt").unlink()

        (self.root / "nested").mkdir()
        with self.assertRaises(policy.SarifPolicyError):
            policy.validate_output_directory(str(self.root))

    def test_file_symlink_and_directory_symlink_refuse(self):
        outside = pathlib.Path(self.temporary.name + "-outside.sarif")
        outside.write_text(json.dumps(sarif_document()), encoding="utf-8")
        try:
            (self.root / "go.sarif").symlink_to(outside)
            with self.assertRaises(policy.SarifPolicyError):
                policy.validate_output_directory(str(self.root))
            (self.root / "go.sarif").unlink()

            self.write_document()
            linked_root = pathlib.Path(self.temporary.name + "-link")
            linked_root.symlink_to(self.root, target_is_directory=True)
            try:
                with self.assertRaises(policy.SarifPolicyError):
                    policy.validate_output_directory(str(linked_root))
            finally:
                linked_root.unlink()
        finally:
            outside.unlink(missing_ok=True)

    def test_hard_link_and_fifo_refuse_as_nonexclusive_or_nonregular(self):
        outside = pathlib.Path(self.temporary.name + "-outside.sarif")
        outside.write_text(json.dumps(sarif_document()), encoding="utf-8")
        try:
            os.link(outside, self.root / "go.sarif")
            with self.assertRaises(policy.SarifPolicyError):
                policy.validate_output_directory(str(self.root))
            (self.root / "go.sarif").unlink()

            if hasattr(os, "mkfifo"):
                os.mkfifo(self.root / "go.sarif")
                with self.assertRaises(policy.SarifPolicyError):
                    policy.validate_output_directory(str(self.root))
        finally:
            outside.unlink(missing_ok=True)

    def test_empty_oversized_invalid_utf8_and_malformed_json_refuse(self):
        target = self.root / "go.sarif"
        payloads = (b"", b"\xff", b"{", b"{}")
        for payload in payloads:
            target.write_bytes(payload)
            with self.subTest(payload=payload):
                with self.assertRaises(policy.SarifPolicyError):
                    policy.validate_output_directory(str(self.root))

        with target.open("wb") as output:
            output.truncate(policy.MAX_SARIF_BYTES + 1)
        with self.assertRaises(policy.SarifPolicyError):
            policy.validate_output_directory(str(self.root))

    def test_main_has_fail_closed_exit_codes(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(policy.main([]), 2)
            self.assertEqual(policy.main([str(self.root)]), 1)
            self.write_document()
            self.assertEqual(policy.main([str(self.root)]), 0)


if __name__ == "__main__":
    unittest.main()
