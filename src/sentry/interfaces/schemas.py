"""
sentry.interfaces.schemas
~~~~~~~~~~~~~~~~~~~~~

:copyright: (c) 2010-2017 by the Sentry Team, see AUTHORS for more details.
:license: BSD, see LICENSE for more details.
"""

from __future__ import absolute_import

import six

CSP_SCHEMA = {
    'type': 'object',
    'properties': {
        'csp-report': {
            'type': 'object',
            'properties': {
                'effective-directive': {
                    'type': 'string',
                    'enum': [
                        'base-uri',
                        'child-src',
                        'connect-src',
                        'default-src',
                        'font-src',
                        'form-action',
                        'frame-ancestors',
                        'img-src',
                        'manifest-src',
                        'media-src',
                        'object-src',
                        'plugin-types',
                        'referrer',
                        'script-src',
                        'style-src',
                        'upgrade-insecure-requests',
                        # 'frame-src', # Deprecated (https://developer.mozilla.org/en-US/docs/Web/Security/CSP/CSP_policy_directives#frame-src)
                        # 'sandbox', # Unsupported
                    ],
                },
                'blocked-uri': {
                    'type': 'string',
                    'default': 'self',  # TODO test that this works and does not interfere with required keys?
                    'not': {
                        'enum': [
                            'about',  # Noise from Chrome about page.
                            'ms-browser-extension',
                        ],
                        'description': "URIs that are pure noise and will never be actionable.",
                    }
                },
                'document-uri': {
                    'type': 'string',
                    'not': {'enum': ['about:blank']}
                },
                'original-policy': {'type': 'string'},
                'referrer': {'type': 'string', 'default': ''},
                'status-code': {'type': 'number'},
                'violated-directive': {'type': 'string', 'default': ''},
                'source-file': {'type': 'string'},
                'line-number': {'type': 'number'},
                'column-number': {'type': 'number'},
                'script-sample': {'type': 'number'},  # Firefox specific key.
            },
            'allOf': [
                {'required': ['effective-directive']},
                {
                    'anyOf': [  # Require at least one of these keys.
                        {'required': ['blocked-uri']},
                        {'required': ['source-file']},
                    ]
                }
            ],
            'additionalProperties': False,  # Don't allow any other keys.
        }
    },
    'required': ['csp-report'],
    'additionalProperties': False,
}

CSP_INTERFACE_SCHEMA = {
    'type': 'object',
    'properties': {k.replace('-', '_'): v for k, v in six.iteritems(CSP_SCHEMA['properties']['csp-report']['properties'])},
    'allOf': [
        {'required': ['effective_directive']},
        {
            'anyOf': [
                # At least one of these is required.
                {'required': ['blocked_uri']},
                {'required': ['source_file']},
            ]
        }
    ],
    'additionalProperties': False,  # Don't allow any other keys.
}

# RFC7469 Section 3
HPKP_SCHEMA = {
    'type': 'object',
    'properties': {
        'date-time': {'type': 'string', },  # TODO validate (RFC3339)
        'hostname': {'type': 'string'},
        'port': {'type': 'number'},
        'effective-expiration-date': {'type': 'string', },  # TODO validate (RFC3339)
        'include-subdomains': {'type': 'boolean'},
        'noted-hostname': {'type': 'string'},
        'served-certificate-chain': {
            'type': 'array',
            'items': {'type': 'string'}
        },
        'validated-certificate-chain': {
            'type': 'array',
            'items': {'type': 'string'}
        },
        'known-pins': {
            'type': 'array',
            'items': {'type': 'string'}  # TODO regex this string for 'pin-sha256="ABC123"' syntax
        },
    },
    'required': ['hostname'],  # TODO fill in more required keys
    'additionalProperties': False,  # Don't allow any other keys.
}

HPKP_INTERFACE_SCHEMA = {
    'type': 'object',
    'properties': {k.replace('-', '_'): v for k, v in six.iteritems(HPKP_SCHEMA['properties'])},
    'required': ['hostname'],  # TODO fill in more required keys
    'additionalProperties': False,  # Don't allow any other keys.
}

EXPECT_CT_SCHEMA = {
    'type': 'object',
    'properties': {
        'expect-ct-report': {
            'type': 'object',
            'properties': {
                'date-time': {'type': 'string', },  # TODO validate (RFC3339)
                'hostname': {'type': 'string'},
                'port': {'type': 'number'},
                'effective-expiration-date': {'type': 'string', },  # TODO validate (RFC3339)
                'served-certificate-chain': {
                    'type': 'array',
                    'items': {'type': 'string'}
                },
                'validated-certificate-chain': {
                    'type': 'array',
                    'items': {'type': 'string'}
                },
                'scts': {
                    'type': 'array',
                    'items': {
                        'type': 'object',
                        'properties': {
                            'version': {'type': 'number'},
                            'status': {
                                'type': 'string',
                                'enum': ['unknown', 'valid', 'invalid'],
                            },
                            'source': {
                                'type': 'string',
                                'enum': ['tls-extension', 'ocsp', 'embedded'],
                            },
                            'serialized_sct': {'type': 'string'},  # Base64
                        },
                        'additionalProperties': False,
                    },
                },
            },
            'required': ['hostname'],
            'additionalProperties': False,
        },
    },
    'additionalProperties': False,
}

EXPECT_CT_INTERFACE_SCHEMA = {
    'type': 'object',
    'properties': {k.replace('-', '_'): v for k, v in
                   six.iteritems(EXPECT_CT_SCHEMA['properties']['expect-ct-report']['properties'])},
    'required': ['hostname'],
    'additionalProperties': False,
}

EXPECT_STAPLE_SCHEMA = {
    'type': 'object',
    'properties': {
        'expect-staple-report': {
            'type': 'object',
            'properties': {
                'date-time': {'type': 'string', },  # TODO validate (RFC3339)
                'hostname': {'type': 'string'},
                'port': {'type': 'number'},
                'effective-expiration-date': {'type': 'string', },  # TODO validate (RFC3339)
                'response-status': {
                    'type': 'string',
                    'enum': [
                        'MISSING',
                        'PROVIDED',
                        'ERROR_RESPONSE',
                        'BAD_PRODUCED_AT',
                        'NO_MATCHING_RESPONSE',
                        'INVALID_DATE',
                        'PARSE_RESPONSE_ERROR',
                        'PARSE_RESPONSE_DATA_ERROR',
                    ],
                },
                'ocsp-response': {},
                'cert-status': {
                    'type': 'string',
                    'enum': [
                        'GOOD',
                        'REVOKED',
                        'UNKNOWN',
                    ],
                },
                'served-certificate-chain': {
                    'type': 'array',
                    'items': {'type': 'string'}
                },
                'validated-certificate-chain': {
                    'type': 'array',
                    'items': {'type': 'string'}
                },
            },
            'required': ['hostname'],
            'additionalProperties': False,
        },
    },
    'additionalProperties': False,
}

EXPECT_STAPLE_INTERFACE_SCHEMA = {
    'type': 'object',
    'properties': {k.replace('-', '_'): v for k, v in
                   six.iteritems(EXPECT_STAPLE_SCHEMA['properties']['expect-staple-report']['properties'])},
    'required': ['hostname'],
    'additionalProperties': False,
}

"""
Schemas for raw request data.

This is to validate input data at the very first stage of ingestion. It can
then be transformed into the requisite interface.
"""
INPUT_SCHEMAS = {
    # These should match SENTRY_INTERFACES keys
    'sentry.interfaces.Csp': CSP_SCHEMA,
    'hpkp': HPKP_SCHEMA,
    'expectct': EXPECT_CT_SCHEMA,
    'expectstaple': EXPECT_STAPLE_SCHEMA,
}

"""
Schemas for interfaces.

Data returned by interface.to_json() or passed into interface.to_python()
should conform to these schemas. Currently this is not enforced everywhere yet.
"""
INTERFACE_SCHEMAS = {
    # These should match SENTRY_INTERFACES keys
    'sentry.interfaces.Csp': CSP_INTERFACE_SCHEMA,
    'hpkp': HPKP_INTERFACE_SCHEMA,
    'expectct': EXPECT_CT_INTERFACE_SCHEMA,
    'expectstaple': EXPECT_STAPLE_INTERFACE_SCHEMA,
}
