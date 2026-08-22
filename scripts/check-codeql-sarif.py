#!/usr/bin/env python3
"""Fail-closed policy for local CodeQL ``analyze`` SARIF output.

The trusted workflow invokes this checker on the absolute ``sarif-output``
directory returned by the pinned CodeQL analyze action when ``upload: never``
is in effect.  The checker deliberately accepts only the single-language Go
layout produced by that action and never follows a symbolic link.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Mapping, Sequence


SARIF_FILENAME = "go.sarif"
SARIF_SCHEMA_URIS = frozenset(
    {
        "https://json.schemastore.org/sarif-2.1.0.json",
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
    }
)
CODEQL_DRIVER = "CodeQL"
CODEQL_ORGANIZATION = "GitHub"
CODEQL_VERSION = "2.26.3"
CODEQL_COLUMN_KINDS = frozenset({"unicodeCodePoints", "utf16CodeUnits"})
HIGH_SECURITY_SEVERITY = Decimal("7.0")
MAX_SARIF_BYTES = 10 * 1024 * 1024
MAX_RULES = 25_000
MAX_RESULTS = 25_000
MAX_EXTENSIONS = 100
MAX_TAGS = 20

TEXT_RE = re.compile(r"[^\x00-\x1f\x7f-\x9f]{1,1024}\Z")
SEVERITY_RE = re.compile(r"(?:0\.[0-9]*[1-9][0-9]*|[1-9](?:\.[0-9]+)?|10(?:\.0+)?)\Z")

SARIF_LOG_KEYS = frozenset({"$schema", "version", "runs", "inlineExternalProperties", "properties"})
RUN_KEYS = frozenset(
    {
        "addresses",
        "artifacts",
        "automationDetails",
        "baselineGuid",
        "columnKind",
        "conversion",
        "defaultEncoding",
        "defaultSourceLanguage",
        "externalPropertyFileReferences",
        "graphs",
        "invocations",
        "language",
        "logicalLocations",
        "newlineSequences",
        "originalUriBaseIds",
        "policies",
        "properties",
        "redactionTokens",
        "results",
        "runAggregates",
        "specialLocations",
        "taxonomies",
        "threadFlowLocations",
        "tool",
        "translations",
        "versionControlProvenance",
        "webRequests",
        "webResponses",
    }
)
TOOL_KEYS = frozenset({"driver", "extensions", "properties"})
COMPONENT_KEYS = frozenset(
    {
        "associatedComponent",
        "contents",
        "dottedQuadFileVersion",
        "downloadUri",
        "fullDescription",
        "fullName",
        "globalMessageStrings",
        "guid",
        "informationUri",
        "language",
        "localizedDataSemanticVersion",
        "locations",
        "minimumRequiredLocalizedDataSemanticVersion",
        "name",
        "notifications",
        "organization",
        "product",
        "productSuite",
        "properties",
        "releaseDateUtc",
        "rules",
        "semanticVersion",
        "shortDescription",
        "supportedTaxonomies",
        "taxa",
        "translationMetadata",
        "version",
    }
)
RULE_KEYS = frozenset(
    {
        "defaultConfiguration",
        "deprecatedGuids",
        "deprecatedIds",
        "deprecatedNames",
        "fullDescription",
        "guid",
        "help",
        "helpUri",
        "id",
        "messageStrings",
        "name",
        "properties",
        "relationships",
        "shortDescription",
    }
)
RESULT_KEYS = frozenset(
    {
        "analysisTarget",
        "attachments",
        "baselineState",
        "codeFlows",
        "correlationGuid",
        "fingerprints",
        "fixes",
        "graphTraversals",
        "graphs",
        "hostedViewerUri",
        "kind",
        "level",
        "locations",
        "message",
        "occurrenceCount",
        "partialFingerprints",
        "properties",
        "provenance",
        "rank",
        "relatedLocations",
        "rule",
        "ruleId",
        "ruleIndex",
        "stacks",
        "suppressions",
        "taxa",
        "webRequest",
        "webResponse",
        "workItemUris",
    }
)
RULE_REFERENCE_KEYS = frozenset({"guid", "id", "index", "properties", "toolComponent"})
COMPONENT_REFERENCE_KEYS = frozenset({"guid", "index", "name", "properties"})


class SarifPolicyError(RuntimeError):
    """A validation failure that must withhold trusted success."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SarifPolicyError(message)


def object_value(value: Any, label: str) -> Mapping[str, Any]:
    require(isinstance(value, dict), f"{label} is not an object")
    return value


def array_value(value: Any, label: str) -> Sequence[Any]:
    require(isinstance(value, list), f"{label} is not an array")
    return value


def bounded_text(value: Any, label: str) -> str:
    require(isinstance(value, str) and TEXT_RE.fullmatch(value) is not None, f"{label} is malformed")
    return value


def exact_index(value: Any, label: str, upper_bound: int) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool) and 0 <= value < upper_bound,
        f"{label} is not a bounded non-negative integer",
    )
    return value


def reject_unknown_keys(value: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    require(not unknown, f"{label} has unsupported SARIF fields: {', '.join(unknown[:8])}")


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SarifPolicyError(f"JSON contains duplicate object key {key!r}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> Any:
    raise SarifPolicyError(f"JSON contains non-finite numeric constant {value!r}")


def parse_json(payload: bytes) -> Mapping[str, Any]:
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=unique_json_object,
            parse_constant=reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SarifPolicyError(f"SARIF is not strict UTF-8 JSON: {error}") from error
    return object_value(value, "SARIF document")


def read_analyze_output(output_directory: str) -> bytes:
    candidate = Path(output_directory)
    require(candidate.is_absolute(), "CodeQL SARIF output directory path is not absolute")

    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        path_stat = os.stat(candidate, follow_symlinks=False)
        require(stat.S_ISDIR(path_stat.st_mode), "CodeQL SARIF output path is not a regular directory")
        directory_fd = os.open(candidate, directory_flags | nofollow)
    except OSError as error:
        raise SarifPolicyError(f"cannot open CodeQL SARIF output directory safely: {error}") from error

    try:
        opened_stat = os.fstat(directory_fd)
        require(
            stat.S_ISDIR(opened_stat.st_mode)
            and (opened_stat.st_dev, opened_stat.st_ino) == (path_stat.st_dev, path_stat.st_ino),
            "CodeQL SARIF output directory changed while it was opened",
        )
        names = os.listdir(directory_fd)
        require(names == [SARIF_FILENAME], f"CodeQL SARIF output must contain only {SARIF_FILENAME}")

        entry_stat = os.stat(SARIF_FILENAME, dir_fd=directory_fd, follow_symlinks=False)
        require(stat.S_ISREG(entry_stat.st_mode), "CodeQL SARIF output is not a regular file")
        require(entry_stat.st_nlink == 1, "CodeQL SARIF output has an unsafe hard-link count")
        require(0 < entry_stat.st_size <= MAX_SARIF_BYTES, "CodeQL SARIF output size is outside the safe bound")

        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
        file_fd = os.open(SARIF_FILENAME, file_flags, dir_fd=directory_fd)
        try:
            before = os.fstat(file_fd)
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_nlink == 1
                and (before.st_dev, before.st_ino) == (entry_stat.st_dev, entry_stat.st_ino),
                "CodeQL SARIF output changed before it was read",
            )
            chunks: list[bytes] = []
            remaining = MAX_SARIF_BYTES + 1
            while remaining:
                chunk = os.read(file_fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(file_fd)
            require(len(payload) <= MAX_SARIF_BYTES, "CodeQL SARIF output exceeds the safe size bound")
            require(
                before.st_size == len(payload) == after.st_size
                and before.st_mtime_ns == after.st_mtime_ns
                and before.st_ctime_ns == after.st_ctime_ns
                and after.st_nlink == 1,
                "CodeQL SARIF output changed while it was read",
            )
        finally:
            os.close(file_fd)

        final_path_stat = os.stat(candidate, follow_symlinks=False)
        require(
            stat.S_ISDIR(final_path_stat.st_mode)
            and (final_path_stat.st_dev, final_path_stat.st_ino) == (opened_stat.st_dev, opened_stat.st_ino),
            "CodeQL SARIF output directory changed after it was read",
        )
        return payload
    except OSError as error:
        raise SarifPolicyError(f"cannot read CodeQL SARIF output safely: {error}") from error
    finally:
        os.close(directory_fd)


def message_text(value: Any, label: str) -> str:
    message = object_value(value, label)
    text = message.get("text")
    require(isinstance(text, str) and 0 < len(text) <= 100_000, f"{label}.text is malformed")
    return text


def security_severity(rule: Mapping[str, Any], label: str) -> tuple[Decimal | None, tuple[str, ...]]:
    properties = object_value(rule.get("properties"), f"{label}.properties")
    tags_value = properties.get("tags", [])
    tags = array_value(tags_value, f"{label}.properties.tags")
    require(len(tags) <= MAX_TAGS, f"{label} has too many tags")
    normalized_tags: list[str] = []
    for index, tag in enumerate(tags):
        normalized_tags.append(bounded_text(tag, f"{label}.properties.tags[{index}]"))
    require(len(set(normalized_tags)) == len(normalized_tags), f"{label} has duplicate tags")

    raw = properties.get("security-severity")
    tagged_security = "security" in normalized_tags
    if raw is None:
        require(not tagged_security, f"{label} is security-tagged but has no security-severity")
        return None, tuple(normalized_tags)
    require(tagged_security, f"{label} has security-severity without the security tag")
    require(isinstance(raw, str) and SEVERITY_RE.fullmatch(raw) is not None, f"{label} security-severity is malformed")
    try:
        value = Decimal(raw)
    except InvalidOperation as error:
        raise SarifPolicyError(f"{label} security-severity is malformed") from error
    require(Decimal("0.0") < value <= Decimal("10.0"), f"{label} security-severity is outside (0.0, 10.0]")
    return value, tuple(normalized_tags)


@dataclass(frozen=True)
class Rule:
    identifier: str
    component_index: int | None
    component_name: str
    component_guid: str | None
    rule_index: int
    rule_guid: str | None
    severity: Decimal | None
    has_query_help: bool
    kind: str


def validate_rule(rule_value: Any, component_index: int | None, component_name: str, rule_index: int) -> Rule:
    label = f"rule {component_name}[{rule_index}]"
    rule = object_value(rule_value, label)
    reject_unknown_keys(rule, RULE_KEYS, label)
    identifier = bounded_text(rule.get("id"), f"{label}.id")
    bounded_text(rule.get("name"), f"{label}.name")
    message_text(rule.get("shortDescription"), f"{label}.shortDescription")
    message_text(rule.get("fullDescription"), f"{label}.fullDescription")
    properties = object_value(rule.get("properties"), f"{label}.properties")
    kind = bounded_text(properties.get("kind"), f"{label}.properties.kind")
    severity, tags = security_severity(rule, label)
    has_query_help = "help" in rule
    if has_query_help:
        help_message = object_value(rule["help"], f"{label}.help")
        message_text(help_message, f"{label}.help")
        help_markdown = help_message.get("markdown")
        require(
            isinstance(help_markdown, str) and 0 < len(help_markdown) <= 1_000_000,
            f"{label}.help.markdown is missing or malformed",
        )
    else:
        require(
            kind == "metric" and "summary" in tags and severity is None,
            f"{label} omits query help but is not an unclassified summary metric",
        )
    if "defaultConfiguration" in rule:
        configuration = object_value(rule["defaultConfiguration"], f"{label}.defaultConfiguration")
        if "level" in configuration:
            require(
                configuration["level"] in ("none", "note", "warning", "error"),
                f"{label} has an invalid default level",
            )
    guid = rule.get("guid")
    require(guid is None or isinstance(guid, str), f"{label}.guid is malformed")
    return Rule(identifier, component_index, component_name, None, rule_index, guid, severity, has_query_help, kind)


def component_rules(
    component_value: Any,
    component_index: int | None,
    label: str,
    *,
    driver: bool,
) -> tuple[str, str | None, list[Rule]]:
    component = object_value(component_value, label)
    reject_unknown_keys(component, COMPONENT_KEYS, label)
    name = bounded_text(component.get("name"), f"{label}.name")
    if driver:
        require(name == CODEQL_DRIVER, "SARIF tool driver is not exact CodeQL")
        require(component.get("organization") == CODEQL_ORGANIZATION, "SARIF tool organization is not GitHub")
        require(
            component.get("semanticVersion") == CODEQL_VERSION,
            f"CodeQL driver semanticVersion is not exactly {CODEQL_VERSION}",
        )
        if "version" in component:
            require(
                component["version"] == CODEQL_VERSION,
                f"CodeQL driver version disagrees with {CODEQL_VERSION}",
            )
    guid = component.get("guid")
    require(guid is None or isinstance(guid, str), f"{label}.guid is malformed")
    rules_value = component.get("rules", [])
    rules = array_value(rules_value, f"{label}.rules")
    require(len(rules) <= MAX_RULES, f"{label} has too many rules")
    parsed = [validate_rule(value, component_index, name, index) for index, value in enumerate(rules)]
    parsed = [
        Rule(
            rule.identifier,
            rule.component_index,
            rule.component_name,
            guid,
            rule.rule_index,
            rule.rule_guid,
            rule.severity,
            rule.has_query_help,
            rule.kind,
        )
        for rule in parsed
    ]
    return name, guid, parsed


def validate_artifacts(run: Mapping[str, Any]) -> dict[int, str]:
    artifacts = array_value(run.get("artifacts"), "SARIF run.artifacts")
    require(len(artifacts) <= MAX_RESULTS * 4, "SARIF run has too many artifacts")
    result: dict[int, str] = {}
    for index, artifact_value in enumerate(artifacts):
        artifact = object_value(artifact_value, f"artifact[{index}]")
        location = object_value(artifact.get("location"), f"artifact[{index}].location")
        artifact_index = exact_index(location.get("index"), f"artifact[{index}].location.index", max(1, len(artifacts)))
        require(artifact_index == index, f"artifact[{index}] has a non-canonical index")
        uri = location.get("uri")
        require(isinstance(uri, str) and 0 < len(uri) <= 4096, f"artifact[{index}].location.uri is malformed")
        require(artifact_index not in result, f"artifact index {artifact_index} is duplicated")
        result[artifact_index] = uri
    return result


def result_rule(
    result: Mapping[str, Any],
    result_index: int,
    rules_by_location: Mapping[tuple[int | None, int], Rule],
    components: Sequence[tuple[str, str | None]],
) -> Rule:
    label = f"result[{result_index}]"
    identifier = bounded_text(result.get("ruleId"), f"{label}.ruleId")
    reference = object_value(result.get("rule"), f"{label}.rule")
    reject_unknown_keys(reference, RULE_REFERENCE_KEYS, f"{label}.rule")
    require(reference.get("id") == identifier, f"{label}.rule.id disagrees with ruleId")
    reference_index = exact_index(reference.get("index"), f"{label}.rule.index", MAX_RULES)
    if "ruleIndex" in result:
        rule_index = exact_index(result["ruleIndex"], f"{label}.ruleIndex", MAX_RULES)
        require(reference_index == rule_index, f"{label}.rule.index disagrees with ruleIndex")

    component_reference = object_value(reference.get("toolComponent"), f"{label}.rule.toolComponent")
    reject_unknown_keys(component_reference, COMPONENT_REFERENCE_KEYS, f"{label}.rule.toolComponent")
    component_index = exact_index(
        component_reference.get("index"),
        f"{label}.rule.toolComponent.index",
        len(components),
    )
    expected_name, expected_guid = components[component_index]
    if "name" in component_reference:
        require(
            component_reference["name"] == expected_name,
            f"{label} component name disagrees with its index",
        )
    if "guid" in component_reference:
        require(
            component_reference["guid"] == expected_guid,
            f"{label} component guid disagrees with its index",
        )

    location = (component_index, reference_index)
    require(location in rules_by_location, f"{label} references a missing rule descriptor")
    rule = rules_by_location[location]
    require(rule.identifier == identifier, f"{label} ruleId does not match its indexed descriptor")
    if "guid" in reference:
        require(reference["guid"] == rule.rule_guid, f"{label} rule guid disagrees with its descriptor")
    require(rule.has_query_help, f"{label} references a rule without pinned query help")
    require(rule.kind != "metric", f"{label} references a metric descriptor as an alert")
    require(rule.severity is not None, f"{label} references a rule without classified security-severity")
    return rule


def validate_result_shape(result: Mapping[str, Any], result_index: int, artifacts: Mapping[int, str]) -> None:
    label = f"result[{result_index}]"
    message_text(result.get("message"), f"{label}.message")
    fingerprints = object_value(result.get("partialFingerprints"), f"{label}.partialFingerprints")
    fingerprint = fingerprints.get("primaryLocationLineHash")
    require(
        isinstance(fingerprint, str) and 0 < len(fingerprint) <= 1024,
        f"{label} has no primary location fingerprint",
    )

    locations = array_value(result.get("locations"), f"{label}.locations")
    require(len(locations) == 1, f"{label} must contain exactly one primary location")
    location = object_value(locations[0], f"{label}.locations[0]")
    physical = object_value(location.get("physicalLocation"), f"{label}.locations[0].physicalLocation")
    artifact = object_value(physical.get("artifactLocation"), f"{label}.locations[0].physicalLocation.artifactLocation")
    artifact_index = exact_index(
        artifact.get("index"),
        f"{label}.locations[0].physicalLocation.artifactLocation.index",
        max(1, len(artifacts)),
    )
    require(artifact_index in artifacts, f"{label} references a missing artifact")
    require(artifact.get("uri") == artifacts[artifact_index], f"{label} artifact uri disagrees with its index")
    region = object_value(physical.get("region"), f"{label}.locations[0].physicalLocation.region")
    start_line = region.get("startLine")
    require(
        isinstance(start_line, int) and not isinstance(start_line, bool) and start_line > 0,
        f"{label} startLine is malformed",
    )


def validate_sarif(document_value: Any) -> tuple[int, int]:
    document = object_value(document_value, "SARIF document")
    reject_unknown_keys(document, SARIF_LOG_KEYS, "SARIF document")
    require(document.get("$schema") in SARIF_SCHEMA_URIS, "SARIF schema URI is not an accepted 2.1.0 schema")
    require(document.get("version") == "2.1.0", "SARIF version is not exactly 2.1.0")
    require("inlineExternalProperties" not in document, "inline external SARIF properties are not accepted")
    runs = array_value(document.get("runs"), "SARIF runs")
    require(len(runs) == 1, "SARIF must contain exactly one CodeQL run")

    run = object_value(runs[0], "SARIF run")
    reject_unknown_keys(run, RUN_KEYS, "SARIF run")
    require("externalPropertyFileReferences" not in run, "external SARIF property files are not accepted")
    properties = object_value(run.get("properties"), "SARIF run.properties")
    require(properties.get("semmle.formatSpecifier") == "sarif-latest", "SARIF was not produced with sarif-latest")
    require(
        run.get("columnKind") in CODEQL_COLUMN_KINDS,
        "SARIF columnKind is not a supported CodeQL coordinate kind",
    )
    if "newlineSequences" in run:
        newline_sequences = array_value(run["newlineSequences"], "SARIF run.newlineSequences")
        require(
            0 < len(newline_sequences) <= 8
            and all(isinstance(value, str) and 0 < len(value) <= 4 for value in newline_sequences),
            "SARIF newlineSequences is malformed",
        )

    tool = object_value(run.get("tool"), "SARIF run.tool")
    reject_unknown_keys(tool, TOOL_KEYS, "SARIF run.tool")
    _, _, driver_rules = component_rules(tool.get("driver"), None, "SARIF tool driver", driver=True)
    require(not driver_rules, "CodeQL rules are not grouped by query pack")
    extensions_value = tool.get("extensions", [])
    extensions = array_value(extensions_value, "SARIF tool.extensions")
    require(0 < len(extensions) <= MAX_EXTENSIONS, "SARIF must contain a bounded, non-empty query-pack set")

    components: list[tuple[str, str | None]] = []
    all_rules = list(driver_rules)
    component_names: set[str] = set()
    component_guids: set[str] = set()
    for component_index, component_value in enumerate(extensions):
        name, guid, rules = component_rules(
            component_value,
            component_index,
            f"SARIF tool extension[{component_index}]",
            driver=False,
        )
        require(name not in component_names, f"SARIF tool extension name {name!r} is duplicated")
        component_names.add(name)
        if guid is not None:
            require(guid not in component_guids, f"SARIF tool extension guid {guid!r} is duplicated")
            component_guids.add(guid)
        components.append((name, guid))
        all_rules.extend(rules)

    require(0 < len(all_rules) <= MAX_RULES, "SARIF must define a bounded, non-empty CodeQL rule set")
    rules_by_location: dict[tuple[int | None, int], Rule] = {}
    rules_by_id: dict[str, Rule] = {}
    for rule in all_rules:
        location = (rule.component_index, rule.rule_index)
        require(location not in rules_by_location, "SARIF rule location is duplicated")
        require(rule.identifier not in rules_by_id, f"SARIF rule id {rule.identifier!r} is ambiguous")
        rules_by_location[location] = rule
        rules_by_id[rule.identifier] = rule

    artifacts = validate_artifacts(run)
    results = array_value(run.get("results"), "SARIF run.results")
    require(len(results) <= MAX_RESULTS, "SARIF has too many results")
    for result_index, result_value in enumerate(results):
        result = object_value(result_value, f"result[{result_index}]")
        reject_unknown_keys(result, RESULT_KEYS, f"result[{result_index}]")
        validate_result_shape(result, result_index, artifacts)
        rule = result_rule(result, result_index, rules_by_location, components)
        require(
            rule.severity < HIGH_SECURITY_SEVERITY,
            f"result[{result_index}] {rule.identifier} has security-severity {rule.severity} (high or critical)",
        )

    return len(all_rules), len(results)


def validate_output_directory(output_directory: str) -> tuple[int, int]:
    return validate_sarif(parse_json(read_analyze_output(output_directory)))


def main(arguments: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if arguments is None else arguments)
    if len(values) != 1:
        print("usage: check-codeql-sarif.py <absolute-analyze-sarif-output-directory>", file=sys.stderr)
        return 2
    try:
        rules, results = validate_output_directory(values[0])
    except (SarifPolicyError, OSError) as error:
        print(f"CodeQL SARIF policy refused: {error}", file=sys.stderr)
        return 1
    print(f"CodeQL SARIF policy passed ({rules} rules, {results} results)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
