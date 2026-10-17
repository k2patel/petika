#!/usr/bin/env python3
"""Validate proposed API schemas and test mappings, not runtime conformance."""
import argparse
import json
from pathlib import Path

from openapi_schema_validator import OAS30Validator
from openapi_spec_validator import validate_spec

ROOT = Path(__file__).resolve().parents[1]


def read(relative):
    return json.loads((ROOT / relative).read_text())


def expand_refs(value, spec):
    if isinstance(value, list):
        return [expand_refs(item, spec) for item in value]
    if isinstance(value, dict):
        if "$ref" in value:
            target = spec
            for part in value["$ref"].removeprefix("#/").split("/"):
                target = target[part]
            return expand_refs(target, spec)
        return {key: expand_refs(item, spec) for key, item in value.items()}
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', type=Path, help='Captured actual requests/responses from the Rust delivery tests')
    args = parser.parse_args()
    spec = read("docs/api/group-key-delivery.openapi.json")
    validate_spec(spec)
    operations = [operation for path in spec["paths"].values()
                  for method, operation in path.items()
                  if method in {"get", "post", "put", "patch", "delete"}]
    ids = [operation["operationId"] for operation in operations]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate operation IDs")
    cases = read("docs/testing/group-key-delivery-cases.json")
    if set(ids) != set(cases["operations"]):
        raise ValueError("Every operation needs exactly one runtime test mapping")
    for operation in operations:
        name = operation["operationId"]
        for kind in ("success", "rejection"):
            entries = cases["operations"][name][kind]
            if not entries or not all(isinstance(v, str) and v.strip() for v in entries):
                raise ValueError(f"{name}: missing {kind} test requirements")
    fixtures = read("docs/testing/group-key-delivery-fixtures.json")
    if not fixtures or {fixture["valid"] for fixture in fixtures} != {True, False}:
        raise ValueError("Positive and negative schema fixtures required")
    if args.runtime:
        fixtures.extend(json.loads(args.runtime.read_text()))
    for fixture in fixtures:
        schema = expand_refs(spec["components"]["schemas"][fixture["schema"]], spec)
        errors = list(OAS30Validator(schema).iter_errors(fixture["value"]))
        if bool(errors) == fixture["valid"]:
            detail = errors[0].message if errors else "invalid fixture was accepted"
            raise ValueError(f'{fixture["name"]}: {detail}')
    print(f"PASS: OpenAPI, {len(ids)} operation mappings, {len(fixtures)} schema fixtures")
    print("Behavioral authorization, crypto, and recovery tests run separately in Cargo and browser CI.")


if __name__ == "__main__":
    main()
