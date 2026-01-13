#!/usr/bin/env python3
"""
GraphQL Introspection and Security Testing Tool
"""

import argparse
import requests
import json
import sys
from typing import Dict, List, Optional
from urllib.parse import urljoin
import warnings
warnings.filterwarnings('ignore')


class GraphQLTester:
    def __init__(self, url: str, auth_token: str = None, proxy: str = None):
        self.url = url
        self.session = requests.Session()
        self.session.verify = False
        self.schema = None
        self.findings = []

        if auth_token:
            self.session.headers['Authorization'] = f'Bearer {auth_token}'

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        self.session.headers['Content-Type'] = 'application/json'

    def query(self, query: str, variables: Dict = None) -> Dict:
        """Execute GraphQL query"""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        resp = self.session.post(self.url, json=payload, timeout=30)
        return resp.json()

    def introspection_query(self) -> Optional[Dict]:
        """Full introspection query"""
        query = '''
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
                directives {
                    name
                    description
                    locations
                    args {
                        ...InputValue
                    }
                }
            }
        }

        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValue
            }
            interfaces {
                ...TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes {
                ...TypeRef
            }
        }

        fragment InputValue on __InputValue {
            name
            description
            type {
                ...TypeRef
            }
            defaultValue
        }

        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                }
                            }
                        }
                    }
                }
            }
        }
        '''

        try:
            result = self.query(query)
            if 'data' in result and result['data'].get('__schema'):
                self.schema = result['data']['__schema']
                self.findings.append({
                    "severity": "MEDIUM",
                    "title": "GraphQL Introspection Enabled",
                    "description": "GraphQL introspection is enabled, exposing the full API schema",
                    "recommendation": "Disable introspection in production environments"
                })
                return self.schema
            return None
        except Exception as e:
            return None

    def simple_introspection(self) -> Optional[Dict]:
        """Simple introspection query"""
        query = '{__schema{types{name,fields{name}}}}'

        try:
            result = self.query(query)
            if 'data' in result:
                return result['data']
            return None
        except:
            return None

    def get_types(self) -> List[Dict]:
        """Get all types from schema"""
        if not self.schema:
            self.introspection_query()

        if not self.schema:
            return []

        types = []
        for t in self.schema.get('types', []):
            if not t['name'].startswith('__'):
                types.append(t)

        return types

    def find_sensitive_fields(self) -> List[Dict]:
        """Find potentially sensitive fields in schema"""
        sensitive_patterns = [
            'password', 'secret', 'token', 'key', 'ssn', 'credit',
            'private', 'internal', 'admin', 'hash', 'salt', 'api_key',
            'access_token', 'refresh_token', 'auth', 'credential'
        ]

        findings = []
        types = self.get_types()

        for t in types:
            type_name = t.get('name', '')
            fields = t.get('fields') or []

            for field in fields:
                field_name = field.get('name', '').lower()

                for pattern in sensitive_patterns:
                    if pattern in field_name or pattern in type_name.lower():
                        finding = {
                            "severity": "HIGH",
                            "title": "Sensitive Field Exposed",
                            "type": type_name,
                            "field": field.get('name'),
                            "description": f"Potentially sensitive field '{field.get('name')}' in type '{type_name}'",
                            "recommendation": "Review access controls for this field"
                        }
                        findings.append(finding)
                        self.findings.append(finding)
                        break

        return findings

    def test_query_depth(self, max_depth: int = 10) -> Dict:
        """Test for query depth limiting"""

        # Build nested query
        nested_query = "{ users { "
        for i in range(max_depth):
            nested_query += "friends { "
        nested_query += "id " + "} " * max_depth + "} }"

        try:
            result = self.query(nested_query)

            if 'errors' not in result:
                finding = {
                    "severity": "MEDIUM",
                    "title": "No Query Depth Limiting",
                    "description": f"Server accepts queries with depth {max_depth}",
                    "recommendation": "Implement query depth limiting to prevent DoS"
                }
                self.findings.append(finding)
                return {"vulnerable": True, "depth_tested": max_depth}

            return {"vulnerable": False, "depth_tested": max_depth}
        except:
            return {"error": "Query failed"}

    def test_batch_queries(self) -> Dict:
        """Test for batch query support"""

        batch_query = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"}
        ]

        try:
            resp = self.session.post(self.url, json=batch_query, timeout=10)
            result = resp.json()

            if isinstance(result, list):
                finding = {
                    "severity": "MEDIUM",
                    "title": "Batch Queries Enabled",
                    "description": "Server accepts batch queries which could be used for brute force",
                    "recommendation": "Disable batch queries or implement rate limiting"
                }
                self.findings.append(finding)
                return {"vulnerable": True, "batch_supported": True}

            return {"vulnerable": False}
        except:
            return {"error": "Batch query test failed"}

    def test_alias_based_attacks(self, query_template: str, count: int = 100) -> Dict:
        """Test alias-based BOLA/enumeration"""

        # Build aliased query
        alias_query = "{ "
        for i in range(count):
            alias_query += f"a{i}: user(id: {i}) {{ id email }} "
        alias_query += "}"

        try:
            result = self.query(alias_query)

            if 'errors' not in result or result.get('data'):
                data = result.get('data', {})
                found_users = [k for k, v in data.items() if v is not None]

                if found_users:
                    finding = {
                        "severity": "HIGH",
                        "title": "Alias-based BOLA",
                        "description": f"Mass data extraction possible via aliases. Found {len(found_users)} users",
                        "recommendation": "Implement authorization checks per-alias"
                    }
                    self.findings.append(finding)
                    return {"vulnerable": True, "users_found": len(found_users)}

            return {"vulnerable": False}
        except:
            return {"error": "Alias test failed"}

    def test_field_suggestions(self) -> List[str]:
        """Extract field suggestions from errors"""

        queries = [
            "{ user { unknown_field } }",
            "{ users { invalid } }",
            "{ test }",
        ]

        suggestions = []

        for q in queries:
            try:
                result = self.query(q)
                errors = result.get('errors', [])

                for error in errors:
                    message = error.get('message', '')
                    # Extract suggestions like "Did you mean X?"
                    if 'did you mean' in message.lower():
                        suggestions.append(message)
            except:
                continue

        if suggestions:
            finding = {
                "severity": "LOW",
                "title": "Field Suggestions Enabled",
                "description": "Error messages provide field name suggestions",
                "suggestions": suggestions,
                "recommendation": "Disable field suggestions in production"
            }
            self.findings.append(finding)

        return suggestions

    def test_mutations(self) -> List[Dict]:
        """Identify available mutations"""

        if not self.schema:
            self.introspection_query()

        if not self.schema:
            return []

        mutations = []
        mutation_type_name = self.schema.get('mutationType', {}).get('name')

        if mutation_type_name:
            for t in self.schema.get('types', []):
                if t.get('name') == mutation_type_name:
                    for field in t.get('fields', []):
                        mutations.append({
                            "name": field.get('name'),
                            "args": [arg.get('name') for arg in field.get('args', [])],
                            "description": field.get('description')
                        })

        return mutations

    def generate_queries(self) -> List[str]:
        """Generate sample queries from schema"""

        if not self.schema:
            self.introspection_query()

        queries = []
        types = self.get_types()

        query_type_name = self.schema.get('queryType', {}).get('name', 'Query')

        for t in types:
            if t.get('name') == query_type_name:
                for field in t.get('fields', []):
                    field_name = field.get('name')
                    args = field.get('args', [])

                    if args:
                        arg_str = ', '.join([f'{a["name"]}: ""' for a in args[:2]])
                        query = f'{{ {field_name}({arg_str}) {{ id }} }}'
                    else:
                        query = f'{{ {field_name} {{ id }} }}'

                    queries.append(query)

        return queries[:20]  # Limit to 20 queries

    def run_full_assessment(self) -> Dict:
        """Run complete GraphQL security assessment"""

        results = {
            "url": self.url,
            "introspection": None,
            "types": [],
            "mutations": [],
            "sensitive_fields": [],
            "depth_test": {},
            "batch_test": {},
            "findings": []
        }

        # Introspection
        print("[*] Testing introspection...")
        schema = self.introspection_query()
        results["introspection"] = "enabled" if schema else "disabled"

        if schema:
            # Get types
            print("[*] Analyzing schema...")
            results["types"] = [t.get('name') for t in self.get_types()]
            results["mutations"] = self.test_mutations()

            # Find sensitive fields
            print("[*] Scanning for sensitive fields...")
            results["sensitive_fields"] = self.find_sensitive_fields()

        # Test depth limiting
        print("[*] Testing query depth limiting...")
        results["depth_test"] = self.test_query_depth()

        # Test batch queries
        print("[*] Testing batch queries...")
        results["batch_test"] = self.test_batch_queries()

        # Test field suggestions
        print("[*] Testing field suggestions...")
        self.test_field_suggestions()

        results["findings"] = self.findings

        return results


def main():
    parser = argparse.ArgumentParser(description='GraphQL Security Tester')
    parser.add_argument('--url', '-u', required=True, help='GraphQL endpoint URL')
    parser.add_argument('--auth-token', '-t', help='Authorization token')
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('--introspection', '-i', action='store_true',
                        help='Run introspection query only')
    parser.add_argument('--schema-file', '-s', help='Save schema to file')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--full', '-f', action='store_true',
                        help='Run full security assessment')

    args = parser.parse_args()

    tester = GraphQLTester(
        url=args.url,
        auth_token=args.auth_token,
        proxy=args.proxy
    )

    if args.introspection:
        schema = tester.introspection_query()
        if schema:
            if args.schema_file:
                with open(args.schema_file, 'w') as f:
                    json.dump(schema, f, indent=2)
                print(f"Schema saved to {args.schema_file}")
            else:
                print(json.dumps(schema, indent=2))
        else:
            print("Introspection disabled or failed")

    elif args.full:
        results = tester.run_full_assessment()

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to {args.output}")
        else:
            print(json.dumps(results, indent=2))

    else:
        # Quick test
        schema = tester.introspection_query()
        print(f"Introspection: {'enabled' if schema else 'disabled'}")

        if schema:
            types = tester.get_types()
            print(f"Types found: {len(types)}")

            sensitive = tester.find_sensitive_fields()
            print(f"Sensitive fields: {len(sensitive)}")


if __name__ == '__main__':
    main()
