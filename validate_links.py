import csv
import re
import yaml
import argparse
import logging
from collections import defaultdict
from pydantic import BaseModel, ValidationError
from typing import List, Dict, Optional


class LinkMatcher(BaseModel):
    src: Optional[str] = None
    dst: Optional[str] = None
    dst_if: Optional[str] = None
    count: int


class NodeTemplate(BaseModel):
    name: str
    srcLinkMatchers: Optional[List[LinkMatcher]] = []
    dstLinkMatchers: Optional[List[LinkMatcher]] = []


class Node(BaseModel):
    template: str
    names: List[str]


class ValidationSpec(BaseModel):
    kind: str
    nodeTemplates: List[NodeTemplate]
    nodes: List[Node]


def load_validation_rules(file_path: str) -> ValidationSpec:
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)
        return ValidationSpec(**data)


def load_links(file_path: str) -> List[Dict[str, str]]:
    with open(file_path, 'r') as file:
        reader = csv.DictReader(file)
        return list(reader)


def expand_templates(validation_spec: ValidationSpec) -> List[Dict]:
    expanded_rules = []
    template_map = {template.name: template for template in validation_spec.nodeTemplates}

    for node in validation_spec.nodes:
        template = template_map[node.template]
        for name in node.names:
            for matcher in getattr(template, "srcLinkMatchers", []):
                rule = {
                    "name": f"{template.name}-{name}-src",
                    "src": name,
                    "dst": matcher.dst,
                    "dst_if": matcher.dst_if,
                    "count": matcher.count,
                }
                expanded_rules.append(rule)

            for matcher in getattr(template, "dstLinkMatchers", []):
                rule = {
                    "name": f"{template.name}-{name}-dst",
                    "src": matcher.src,
                    "dst": name,
                    "dst_if": matcher.dst_if,
                    "count": matcher.count,
                }
                expanded_rules.append(rule)

    return expanded_rules


def validate_links(links: List[Dict[str, str]], expanded_rules: List[Dict]):
    results = defaultdict(int)

    for link in links:
        for rule in expanded_rules:
            if (
                (not rule["src"] or re.match(rule["src"], link["src_name"]))
                and (not rule["dst"] or re.match(rule["dst"], link["dst_name"]))
                and (not rule["dst_if"] or re.match(rule["dst_if"], link["dst_if"]))
            ):
                results[rule["name"]] += 1

    for rule in expanded_rules:
        rule_name = rule["name"]
        expected_count = rule["count"]
        actual_count = results[rule_name]
        if actual_count != expected_count:
            logger.error(f"Rule '{rule_name}' failed: expected {expected_count}, got {actual_count}")
        else:
            logger.info(f"Rule '{rule_name}' passed: expected {expected_count}, got {actual_count}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(description="Validate links against rules.")
    parser.add_argument("--rule_file", help="Path to the YAML file containing validation rules.", required=True)
    parser.add_argument("--link_file", help="Path to the CSV file containing links.", required=True)
    args = parser.parse_args()

    try:
        validation_spec = load_validation_rules(args.rule_file)
        links = load_links(args.link_file)

        expanded_rules = expand_templates(validation_spec)
        validate_links(links, expanded_rules)
    except ValidationError as e:
        logger.error(f"Validation Error: {e}")
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")


