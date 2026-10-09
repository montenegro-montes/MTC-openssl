#!/usr/bin/env python3
"""Rotating paired X.509/MTC landmark/MTC standalone browser campaign."""
import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path
import socket
import statistics
import subprocess
import sys

sys.dont_write_bytecode = True
import browser_validation as bv
import browser_pcap as pcap

PREFIX = 'chromium-browser-measurements-'
FORMAL_X509_FIXTURE_SET = 'chromium-x509-depth-matrix-v1'
CAMPAIGN_PROFILES = ('ecdsa-p256', 'ecdsa-p384', 'mldsa44', 'mldsa65', 'mldsa87')
CASES = ('x509', 'mtc-landmark', 'mtc-standalone')
MTC_CASES = ('mtc-landmark', 'mtc-standalone')
PRIMARY = tuple('url_linked_'+name for name in pcap.METRICS)
SECONDARY = (*pcap.METRICS, 'connection_count', 'url_linked_connection_count',
             'auxiliary_tls_only_connection_count', 'aborted_before_tls_completion_connection_count')
METRICS = (*PRIMARY, *SECONDARY)
DECOMPOSITION = tuple('url_linked_'+name for name in pcap.DECOMPOSITION)
COMPARISON = pcap.COMPARISON_FIELDS
COMPARISON_NUMERIC = tuple(key for key in COMPARISON
                           if key not in ('tcp_stream', 'client_random', 'analysis_status', 'analysis_error'))
CSV_OMITTED = {
    'url_linked_server_initial_flight_tcp_payload_bytes',
    'url_linked_client_post_server_flight_tls_payload_bytes',
    'url_linked_http_request_tcp_payload_bytes',
    'url_linked_http_response_tcp_payload_bytes',
    'browser_navigation_to_clienthello_ms',
}
CSV_DECOMPOSITION = tuple(key for key in DECOMPOSITION if key not in CSV_OMITTED)
CSV_COMPARISON = tuple(key for key in COMPARISON if key not in CSV_OMITTED)
CSV_COMPARISON_NUMERIC = tuple(key for key in COMPARISON_NUMERIC if key not in CSV_OMITTED)
META = ('pair', 'pair_index', 'execution_order', 'order_within_pair', 'case',
        'mtc_trust_mode', 'credential', 'anchor', 'requested_tai',
        'selected_tai', 'signature_profile', 'key_establishment',
        'key_exchange_group', 'depth', 'run_id', 'timestamp',
        'result_directory', 'capture_sha256', 'status', 'pair_complete',
        'fixture', 'reason')
PAIR_FIELDS = ('pair', 'pair_index', 'execution_order', 'signature_profile', 'key_establishment', 'key_exchange_group', 'depth',
               *(f'{metric}_{suffix}' for metric in (*PRIMARY, *CSV_DECOMPOSITION, *CSV_COMPARISON_NUMERIC)
                 for suffix in ('mtc', 'x509', 'delta',
                                'mtc_landmark', 'mtc_standalone',
                                'mtc_landmark_vs_x509_delta',
                                'mtc_standalone_vs_x509_delta',
                                'mtc_landmark_vs_mtc_standalone_delta')))
BYTE_DEFINITION = 'Observed TCP payload bytes including retransmissions, excluding link/IP/TCP headers.'

META_DEFINITIONS = {
    'pair': ('integer', 'none', 'One-based round number within the profile and phase.'),
    'pair_index': ('integer', 'none', 'Stable one-based round identifier; equal to pair in the current schema.'),
    'execution_order': ('integer or string', 'none', 'For run rows, campaign-wide ordinal execution number; in pairs.csv, the ordered scenario sequence joined by arrows.'),
    'order_within_pair': ('integer', 'none', 'One-based position of this scenario in the deterministic three-scenario rotation.'),
    'case': ('string', 'none', 'Scenario: x509, mtc-landmark, or mtc-standalone.'),
    'mtc_trust_mode': ('string', 'none', 'MTC trust mode (landmark or standalone); blank for X.509.'),
    'credential': ('path', 'none', 'Exact server credential file selected for this execution.'),
    'anchor': ('path', 'none', 'MTC Chromium anchor file; blank for X.509, whose trust is recorded through CACertificates metadata.'),
    'requested_tai': ('identifier', 'none', 'Expected Requested Trust Anchor Identifier advertised by Chromium; blank for X.509.'),
    'selected_tai': ('identifier', 'none', 'Expected server-selected Trust Anchor Identifier; blank for X.509.'),
    'signature_profile': ('string', 'none', 'Credential signature profile used by the scenario.'),
    'key_establishment': ('string', 'none', 'Campaign selector for X25519 or X25519+ML-KEM768.'),
    'key_exchange_group': ('string', 'none', 'OpenSSL name of the group to which the server was restricted.'),
    'depth': ('integer', 'certificates including root', 'Configured X.509 path depth. It does not alter MTC N=16.'),
    'run_id': ('string', 'none', 'Campaign/result-relative unique identifier for this execution.'),
    'timestamp': ('ISO 8601 UTC', 'none', 'Time recorded immediately before the execution starts.'),
    'result_directory': ('path', 'none', 'Directory containing raw evidence for this execution.'),
    'capture_sha256': ('hex SHA-256', 'none', 'Digest of the retained PCAP/PCAPNG; blank if capture analysis did not complete.'),
    'status': ('string', 'none', 'Observed outcome, normally PASS or INCONCLUSIVE; failures are never replaced.'),
    'pair_complete': ('boolean', 'none', 'True only after every scenario in the round completed successfully.'),
    'fixture': ('path', 'none', 'Fixture root from which the selected credential and key were loaded.'),
    'reason': ('string', 'none', 'Failure/inconclusive diagnostic; blank on success.'),
    'phase': ('string', 'none', 'warmup in warmups.csv. Warmups are excluded from measured statistics.'),
}

HANDSHAKE_DEFINITIONS = {
    'tcp_handshake_ms': ('number', 'ms', 'First SYN to the unique ACK completing the TCP three-way handshake.'),
    'tcp_syn_to_clienthello_ms': ('number', 'ms', 'First SYN to the correlated TLS ClientHello.'),
    'tls_clienthello_to_client_finished_ms': ('number', 'ms', 'ClientHello to client Finished, using capture timestamps.'),
    'tcp_syn_to_first_application_request_ms': ('number', 'ms', 'First SYN to the first identifiable HTTP request.'),
    'tls_client_handshake_bytes': ('integer', 'bytes', 'Logical complete TLS records sent by the client from ClientHello through client Finished, reassembled once.'),
    'tls_server_handshake_bytes': ('integer', 'bytes', 'Logical complete TLS records sent by the server in the same interval, reassembled once.'),
    'tls_handshake_bytes': ('integer', 'bytes', 'Sum of logical client and server handshake-record bytes.'),
    'tls_client_handshake_wire_bytes': ('integer', 'frame.len bytes', 'On-wire frame lengths for client payload frames in the handshake interval, including retransmissions.'),
    'tls_server_handshake_wire_bytes': ('integer', 'frame.len bytes', 'On-wire frame lengths for server payload frames in the handshake interval, including retransmissions.'),
    'tls_handshake_wire_bytes': ('integer', 'frame.len bytes', 'Sum of client and server handshake wire bytes.'),
    'tcp_handshake_wire_bytes': ('integer', 'frame.len bytes', 'On-wire lengths of SYN, SYN/ACK, and the ACK completing TCP establishment.'),
    'connection_handshake_wire_bytes': ('integer', 'frame.len bytes', 'Union of TCP-establishment and TLS-handshake frames; a data-bearing completing ACK is counted once.'),
    'tls_client_handshake_packets': ('integer', 'frames', 'Client payload frames in the analyzed TLS handshake interval.'),
    'tls_server_handshake_packets': ('integer', 'frames', 'Server payload frames in the analyzed TLS handshake interval.'),
    'tls_handshake_packets': ('integer', 'frames', 'Total payload frames in the analyzed TLS handshake interval.'),
    'tls_client_certificate_bytes': ('integer', 'bytes', 'Complete client TLS Certificate handshake message (four-byte handshake header included); zero when absent.'),
    'tls_server_certificate_bytes': ('integer', 'bytes', 'Complete server TLS Certificate handshake message (four-byte handshake header included); not CertificateVerify.'),
    'tcp_stream': ('integer', 'none', 'tshark tcp.stream identifier for the uniquely correlated connection.'),
    'client_random': ('64 lowercase hex characters', 'none', 'TLS ClientHello random used to correlate PCAP, NetLog, and server evidence.'),
    'analysis_status': ('string', 'none', 'OK only when fail-closed handshake extraction succeeds; otherwise ERROR.'),
    'analysis_error': ('string', 'none', 'Fail-closed analyzer diagnostic; blank when analysis_status is OK.'),
    'tcp_retransmission_packets': ('integer', 'frames', 'Frames in the handshake interval flagged by tshark as retransmission, fast retransmission, or spurious retransmission.'),
    'browser_process_wall_ms': ('number', 'ms', pcap.COMPARISON_DEFINITIONS['browser_process_wall_ms']),
    'browser_ssl_connect_ms': ('number', 'ms', pcap.COMPARISON_DEFINITIONS['browser_ssl_connect_ms']),
    'browser_request_to_response_headers_ms': ('number', 'ms', pcap.COMPARISON_DEFINITIONS['browser_request_to_response_headers_ms']),
}


def metric_definition(field):
    if field in META_DEFINITIONS:
        return META_DEFINITIONS[field]
    if field in HANDSHAKE_DEFINITIONS:
        return HANDSHAKE_DEFINITIONS[field]
    counts = {
        'connection_count': 'All target TCP connections classified by the capture analysis.',
        'url_linked_connection_count': 'Connections linked by NetLog to the requested navigation.',
        'auxiliary_tls_only_connection_count': 'TLS-completing target connections not linked to the requested navigation.',
        'aborted_before_tls_completion_connection_count': 'Target connections that did not complete the required TLS evidence.'}
    if field in counts:
        return ('integer', 'connections', counts[field])
    url_linked = field.startswith('url_linked_')
    base = field.removeprefix('url_linked_')
    scope = ('Summed only over successful connections linked by NetLog to the requested URL. '
             if url_linked else
             'Summed over every target TLS connection classified in the capture. ')
    if base in pcap.METRICS:
        if base.startswith('tcp_packets_'):
            direction = base.removeprefix('tcp_packets_').replace('_', ' ')
            return ('integer', 'frames', scope + 'TCP frame count, direction: ' + direction + '.')
        if base.startswith('tcp_payload_bytes_'):
            direction = base.removeprefix('tcp_payload_bytes_').replace('_', ' ')
            return ('integer', 'bytes', scope + 'TCP payload bytes including retransmissions and excluding link/IP/TCP headers, direction: ' + direction + '.')
        direction = base.removeprefix('tcp_wire_bytes_').replace('_', ' ')
        return ('integer', 'frame.len bytes', scope + 'Captured on-wire frame lengths including ACK-only, closing, and retransmitted frames, direction: ' + direction + '.')
    if base in pcap.DECOMPOSITION:
        definition = pcap.DECOMPOSITION_DEFINITIONS.get(
            base, pcap.DECOMPOSITION_DEFINITIONS['unavailable_encrypted_components'])
        return ('integer or blank', 'bytes', scope + definition)
    raise KeyError('Undocumented measurement field: ' + field)


PAIR_SUFFIXES = (
    ('_mtc_landmark_vs_mtc_standalone_delta', 'MTC landmark minus MTC standalone.'),
    ('_mtc_standalone_vs_x509_delta', 'MTC standalone minus X.509.'),
    ('_mtc_landmark_vs_x509_delta', 'MTC landmark minus X.509.'),
    ('_mtc_standalone', 'Value for MTC standalone.'),
    ('_mtc_landmark', 'Value for MTC landmark.'),
    ('_delta', 'Legacy alias: MTC landmark minus X.509.'),
    ('_x509', 'Value for X.509.'),
    ('_mtc', 'Legacy alias: value for MTC landmark.'),
)


def pair_field_definition(field):
    if field in META_DEFINITIONS:
        return META_DEFINITIONS[field]
    for suffix, meaning in PAIR_SUFFIXES:
        if field.endswith(suffix):
            value_type, unit, definition = metric_definition(field[:-len(suffix)])
            return value_type, unit, meaning + ' Base metric: ' + definition
    raise KeyError('Undocumented pair field: ' + field)


def dictionary_table(fields, resolver):
    lines = ['| Field | Type | Unit | Definition and interpretation |',
             '|---|---|---|---|']
    for field in fields:
        value_type, unit, definition = resolver(field)
        lines.append(f'| `{field}` | {value_type} | {unit} | {definition} |')
    return '\n'.join(lines)


SUMMARY_DEFINITIONS = {
    'status': 'Final campaign status.', 'overall_pass': 'True only when the campaign completed without a fail-closed error.',
    'started_at': 'UTC campaign start timestamp.', 'finished_at': 'UTC report finalization timestamp.',
    'run_id': 'Result-directory identifier.', 'reason': 'Top-level failure reason when present.',
    'requested_pairs': 'Requested measured rounds across all profiles.', 'requested_runs': 'Requested measured scenario executions.',
    'pairs_per_profile': 'Measured rounds requested for each profile.', 'total_pairs': 'Measured rounds across profiles.',
    'total_measurements': 'Requested measured scenario executions across profiles.', 'warmups': 'CLI warmup-round count.',
    'warmups_per_profile': 'Warmup rounds per profile.', 'total_warmup_pairs': 'Warmup rounds across profiles.',
    'total_warmup_runs': 'Warmup scenario executions across profiles.', 'completed_pairs': 'Complete PASS measured rounds written to pairs.csv.',
    'attempted_runs': 'Measured executions attempted.', 'pass_runs': 'Measured executions with PASS status.',
    'failed_or_inconclusive_runs': 'Measured executions not marked PASS.', 'attempted_warmup_runs': 'Warmup executions attempted.',
    'pass_warmup_runs': 'Warmup executions with PASS status.', 'failed_or_inconclusive_warmup_runs': 'Warmup executions not marked PASS.',
    'profiles': 'Ordered signature profiles included.', 'scenarios': 'Ordered authentication scenarios included.',
    'key_establishment': 'Campaign key-establishment selector.', 'depth': 'X.509 path depth including root.',
    'fixture_set': 'Required formal X.509 fixture-set identifier.', 'byte_definition': 'Definition governing aggregate TCP payload-byte fields.',
    'tls': 'Configured TLS version, cipher, group, tickets, authentication, port, and NetLog group identifiers.',
    'x509_trust_mode': 'How Chromium X.509 trust was established.', 'certificate_verification_bypass': 'Whether certificate verification was bypassed; false for valid campaigns.',
    'capture_backend': 'Detected capture interface/tools and readiness guidance; not measurement data.',
    'order_policy': 'Deterministic scenario-order policy.', 'chromium': 'Executable path, hash, source commit, and hash scope.',
    'credentials': 'Per-profile validated X.509 and separate landmark/standalone MTC credential records.',
    'x509_policies': 'Per-profile verified Chromium CACertificates policy evidence.',
    'input_sha256': 'Per-profile mapping from every measured input path to its campaign-start SHA-256.',
    'warmup_results': 'Per-warmup identity, order, status, reason, and evidence-directory records.',
    'warmup_policy': 'Fail-closed warmup and exclusion policy.', 'statistics_scope': 'Population admitted to descriptive statistics.',
    'descriptive_statistics': 'profile -> scenario -> aggregate metric -> {n, minimum, maximum, mean, median, sample_stdev}.',
    'paired_delta_statistics': 'profile -> comparison -> URL-linked metric -> descriptive statistics over complete paired deltas.',
    'decomposition_definitions': 'Authoritative prose definitions for optional URL-linked decomposition.',
    'comparison_definitions': 'Authoritative scope and timing definitions shared with browser PCAP analysis.',
    'handshake_analysis_ok_runs': 'Number of accepted measured rows whose shared handshake analyzer returned OK.',
    'comparison_statistics': 'profile -> scenario -> comparable handshake/browser metric -> descriptive statistics over available values.',
}

SUMMARY_NESTED_DEFINITIONS = (
    ('tls.version', 'Configured TLS protocol version.'),
    ('tls.cipher', 'Configured TLS 1.3 cipher suite.'),
    ('tls.group', 'OpenSSL group name enforced by the server.'),
    ('tls.key_establishment', 'Stable campaign selector for the key-establishment configuration.'),
    ('tls.key_establishment_label', 'Human-readable key-establishment label.'),
    ('tls.netlog_group', 'Numeric group identifier required in Chromium NetLog evidence.'),
    ('tls.port', 'Loopback TCP server port.'),
    ('tls.tickets', 'Whether TLS session tickets are enabled.'),
    ('tls.client_authentication', 'Whether client-certificate authentication is enabled.'),
    ('chromium.executable', 'Resolved Chromium executable path.'),
    ('chromium.sha256', 'SHA-256 of the Chromium launcher/executable fixed at campaign start.'),
    ('chromium.commit', 'Git commit discovered from the executable checkout.'),
    ('chromium.hash_scope', 'Explicit boundary of what the Chromium hash covers.'),
    ('capture_backend.platform', 'Operating-system capture platform.'),
    ('capture_backend.interface', 'Loopback interface selected for capture.'),
    ('capture_backend.capture_filter', 'BPF filter restricting capture traffic.'),
    ('capture_backend.dumpcap', 'Resolved dumpcap path or null when unavailable.'),
    ('capture_backend.tcpdump', 'Resolved tcpdump path or null when unavailable.'),
    ('capture_backend.tshark', 'Resolved tshark path used for offline extraction.'),
    ('capture_backend.permissions', 'Pre-run permission status text; runtime capture remains authoritative.'),
    ('capture_backend.instruction', 'Operator guidance when capture requirements are unavailable.'),
    ('credentials.<profile>.<scenario>.fixture', 'Validated fixture root.'),
    ('credentials.<profile>.<scenario>.profile', 'Cryptographic signature profile asserted and validated.'),
    ('credentials.<profile>.<scenario>.cert', 'Selected server credential path.'),
    ('credentials.<profile>.<scenario>.key', 'Matching private-key path.'),
    ('credentials.<profile>.<scenario>.root', 'X.509 root path; X.509 only.'),
    ('credentials.<profile>.<scenario>.intermediates', 'X.509 intermediate bundle path or null; X.509 only.'),
    ('credentials.<profile>.<scenario>.trust', 'Typed MTC trust bundle path; MTC only.'),
    ('credentials.<profile>.<scenario>.anchor', 'Canonical Chromium MTC anchor path; MTC only.'),
    ('credentials.<profile>.<scenario>.*_sha256', 'SHA-256 of the named credential, key, trust, anchor, validation, or root artifact.'),
    ('credentials.<profile>.<scenario>.fixture_set', 'Formal X.509 fixture-set identifier.'),
    ('credentials.<profile>.<scenario>.depth', 'Validated X.509 path depth including root.'),
    ('credentials.<profile>.<scenario>.intermediate_count', 'Number of transmitted X.509 intermediates.'),
    ('credentials.<profile>.<scenario>.root_ca', 'Whether the root has the required CA constraints.'),
    ('credentials.<profile>.<scenario>.root_self_signature_verified', 'Whether the root self-signature was verified.'),
    ('credentials.<profile>.<scenario>.mode', 'MTC trust mode: landmark or standalone.'),
    ('credentials.<profile>.<scenario>.tree_size', 'MTC Merkle tree size N.'),
    ('credentials.<profile>.<scenario>.leaf', 'Selected MTC leaf index.'),
    ('credentials.<profile>.<scenario>.ca_id', 'MTC certification-authority identifier.'),
    ('credentials.<profile>.<scenario>.requested_tai', 'Expected requested Trust Anchor Identifier.'),
    ('credentials.<profile>.<scenario>.selected_tai', 'Expected selected Trust Anchor Identifier.'),
    ('credentials.<profile>.<scenario>.validation_evidence', 'Path to prior cryptographic validation evidence.'),
    ('credentials.<profile>.<scenario>.complete_evidence', 'Whether the selected validation inventory is complete.'),
    ('credentials.<profile>.<scenario>.fixture_hash_status', 'Fixture inventory comparison result.'),
    ('credentials.<profile>.<scenario>.verification_source', 'Provenance statement for reused prevalidated evidence.'),
    ('credentials.<profile>.<scenario>.origin', 'Selection/reuse origin.'),
    ('credentials.<profile>.<scenario>.anchor_origin', 'Canonical anchor reuse/generation origin.'),
    ('credentials.<profile>.<scenario>.image_id', 'Pinned validation/generation container image identifier.'),
    ('credentials.<profile>.<scenario>.hostname', 'Validated server identity.'),
    ('credentials.<profile>.<scenario>.hostname_validation', 'Whether hostname validation succeeded.'),
    ('credentials.<profile>.<scenario>.key_match', 'Whether credential and private key match.'),
    ('credentials.<profile>.<scenario>.SAN', 'Validated Subject Alternative Names.'),
    ('credentials.<profile>.<scenario>.KU', 'Validated Key Usage values.'),
    ('credentials.<profile>.<scenario>.EKU', 'Validated Extended Key Usage values.'),
    ('credentials.<profile>.<scenario>.not_before / not_after', 'Validated credential validity bounds.'),
    ('x509_policies.<profile>.x509_trust_mode', 'Selected Chromium X.509 trust mechanism.'),
    ('x509_policies.<profile>.policy_name', 'Managed policy name, CACertificates.'),
    ('x509_policies.<profile>.policy_applied', 'Whether the exact fixture root was found in effective policy.'),
    ('x509_policies.<profile>.policy_sources', 'Policy documents inspected by the platform abstraction.'),
    ('x509_policies.<profile>.policy_root_der_sha256', 'SHA-256 of the DER root found in policy.'),
    ('x509_policies.<profile>.fixture_root_pem_sha256', 'SHA-256 of the selected root PEM artifact.'),
    ('x509_policies.<profile>.platform_trust_store', 'Whether platform trust-store trust is being used.'),
    ('x509_policies.<profile>.certificate_verification_bypass', 'Whether Chromium certificate verification was bypassed.'),
    ('input_sha256.<profile>.<absolute path>', 'Campaign-start SHA-256 for each credential, key, anchor, trust object, root, intermediate bundle, and Chromium executable.'),
    ('warmup_results[].phase/profile/case/pair_index/execution_order', 'Warmup identity and ordering fields.'),
    ('warmup_results[].status/reason/result_directory', 'Warmup outcome, diagnostic, and retained evidence location.'),
    ('descriptive_statistics.<profile>.<scenario>.<metric>', 'Statistics for an aggregate metric over complete PASS measured rounds.'),
    ('paired_delta_statistics.<profile>.<comparison>.<metric>', 'Statistics for paired left-minus-right URL-linked metric differences.'),
    ('comparison_statistics.<profile>.<scenario>.<metric>', 'Statistics for available shared handshake or browser metrics.'),
    ('<statistics>.n', 'Number of admitted non-null observations.'),
    ('<statistics>.minimum / maximum', 'Minimum and maximum admitted values.'),
    ('<statistics>.mean / median', 'Arithmetic mean and median of admitted values.'),
    ('<statistics>.sample_stdev', 'Sample standard deviation; null when n is one.'),
    ('decomposition_definitions.<name>', 'Definition copied from the capture analyzer for the named optional decomposition concept.'),
    ('comparison_definitions.<name>', 'Definition copied from the capture analyzer for the named comparison scope or timing concept.'),
)


def data_dictionary(summary):
    measurement_fields = (*META, *METRICS, *CSV_DECOMPOSITION, *CSV_COMPARISON)
    warmup_fields = ('phase', *measurement_fields)
    missing_summary = sorted(set(summary) - set(SUMMARY_DEFINITIONS))
    if missing_summary:
        raise ValueError('Undocumented summary.json fields: ' + ', '.join(missing_summary))
    summary_lines = ['| Field | Definition |', '|---|---|']
    for field in summary:
        summary_lines.append(f'| `{field}` | {SUMMARY_DEFINITIONS[field]} |')
    nested_lines = ['| JSON path pattern | Definition |', '|---|---|']
    nested_lines.extend(f'| `{path}` | {definition} |'
                        for path, definition in SUMMARY_NESTED_DEFINITIONS)
    return (
        '## Data dictionary\n\n'
        'Blank CSV cells and JSON `null` mean unavailable or inapplicable evidence; they never mean zero. '
        'All byte counters are integers. Delta signs are always left scenario minus right scenario.\n\n'
        '### measurements.csv\n\nOne row per attempted measured scenario execution.\n\n'
        + dictionary_table(measurement_fields, metric_definition)
        + '\n\n### warmups.csv\n\nThe schema equals measurements.csv plus `phase`; rows are evidence only and never enter statistics.\n\n'
        + dictionary_table(warmup_fields, metric_definition)
        + '\n\n### pairs.csv\n\nOne row per complete PASS measured round. Every scenario value and delta is derived from the three rows sharing profile and pair_index.\n\n'
        + dictionary_table(PAIR_FIELDS, pair_field_definition)
        + '\n\n### summary.json\n\nNested statistical leaves use the exact metric definitions above. '
          '`sample_stdev` is the sample standard deviation and is null for n=1.\n\n'
        + '\n'.join(summary_lines)
        + '\n\n#### summary.json nested fields\n\n'
        + '\n'.join(nested_lines) + '\n')


def existing_mtc(repo, image, profile, trust_mode='landmark'):
    try:
        selected, _ = bv.preselect_mtc_fixture(repo, profile, trust_mode)
    except ValueError as error:
        raise ValueError(
            f'profile={profile}: missing valid MTC N=16 {trust_mode} leaf 0 fixture; '
            'browser-measurements is reuse-only/fail-closed. Prepare it with: '
            f'bin/browser_client/mt-chromium-setup browser-validation credentials --profile {profile}. '
            f'Reason: {error}') from error
    if trust_mode == 'landmark':
        with bv.DockerOpenSSLBatch(image) as openssl:
            validated = bv.validate_mtc(
                Path(selected['fixture']), profile, image, openssl=openssl)
    else:
        validated = bv.prevalidated_mtc(
            selected['fixture'], selected['validation_evidence'], profile,
            'standalone')
    validated.update(anchor=selected['anchor'], anchor_sha256=selected['anchor_sha256'],
                     anchor_origin=selected['anchor_origin'], origin='reused-prechecked')
    return validated


def profile_run_preconditions(repo, image, profile, depth, fixture_set):
    landmark = existing_mtc(repo, image, profile, 'landmark')
    standalone = existing_mtc(repo, image, profile, 'standalone')
    try:
        fixture = bv.precheck_formal_x509_fixture(
            repo, profile, depth, fixture_set)
    except ValueError as error:
        setup = (f'bin/browser_client/mt-chromium-setup x509-fixtures generate-matrix '
                 f'--fixture-set {fixture_set} --output NEW_PATH'
                 if fixture_set == FORMAL_X509_FIXTURE_SET else
                 f'bin/browser_client/mt-chromium-setup x509-fixtures generate '
                 f'--profile {profile} --fixture-set {fixture_set} --output NEW_PATH')
        raise ValueError(
            f'Missing valid X509 fixture: fixture_set={fixture_set}, '
            f'profile={profile}, depth={depth}. browser-measurements is '
            f'reuse-only/fail-closed; prepare it with: {setup}. Reason: {error}') from error
    with bv.DockerOpenSSLBatch(image) as openssl:
        selected = bv.validate_x509(
            fixture, profile=profile, depth=depth, image=image,
            fixture_set=fixture_set, openssl=openssl)
    selected['origin'] = 'reused-formal-fixture-set'
    policy = bv.chromium_ca_policy(selected['root'])
    return dict(mtc_landmark=landmark, mtc_standalone=standalone,
                x509=selected), policy


def campaign_preconditions(repo, image, profiles, depth, fixture_set):
    prepared = {}
    for profile in profiles:
        try:
            prepared[profile] = profile_run_preconditions(
                repo, image, profile, depth, fixture_set)
        except Exception as error:
            raise ValueError(f'profile={profile}: {error}') from error
    return prepared


def campaign_totals(profiles, pairs, warmups=0):
    total_pairs = len(profiles) * pairs
    total_warmup_pairs = len(profiles) * warmups
    return dict(pairs_per_profile=pairs, total_pairs=total_pairs,
                total_measurements=total_pairs * len(CASES), warmups_per_profile=warmups,
                total_warmup_pairs=total_warmup_pairs,
                total_warmup_runs=total_warmup_pairs * len(CASES))


def now():
    return datetime.now(timezone.utc).isoformat()


def order(pair):
    offset = (pair - 1) % len(CASES)
    return CASES[offset:] + CASES[:offset]


def scenario_credentials(credentials, case):
    if case == 'x509':
        # run_case retains an MTC identity argument for its common classifier;
        # X.509 still selects only its own server credential and disables TAI.
        return dict(credentials, mtc=credentials['mtc_landmark']), \
            'x509-positive', credentials['x509']
    key = case.replace('-', '_')
    selected = credentials[key]
    return dict(credentials, mtc=selected), 'mtc-positive', selected


def paired_values(by_case, metric):
    x509 = by_case['x509'][metric]
    landmark = by_case['mtc-landmark'][metric]
    standalone = by_case['mtc-standalone'][metric]
    delta = lambda left, right: (left-right if left is not None
                                  and right is not None else None)
    return {
        metric+'_mtc': landmark,
        metric+'_x509': x509,
        metric+'_delta': delta(landmark, x509),
        metric+'_mtc_landmark': landmark,
        metric+'_mtc_standalone': standalone,
        metric+'_mtc_landmark_vs_x509_delta': delta(landmark, x509),
        metric+'_mtc_standalone_vs_x509_delta': delta(standalone, x509),
        metric+'_mtc_landmark_vs_mtc_standalone_delta': delta(
            landmark, standalone),
    }


def campaign_phases(warmups, pairs):
    return (('warmup', warmups), ('measured', pairs))


def record_measurement_error(output, row, error, phase, execution):
    row.update(status='INCONCLUSIVE' if row['status']=='PASS' else row['status'],
               reason=str(error))
    output.mkdir(exist_ok=True)
    if not (output/'measurement-metadata.json').exists():
        bv.write(output/'measurement-metadata.json', execution)
    bv.write(output/'measurement-error.json',
             dict(error=str(error), status=row['status'], phase=phase,
                  policy='fail-closed; failed executions are never replaced'))


def verify_measurement_inputs(inputs, chromium_executable):
    for path, digest in inputs.items():
        if path != chromium_executable:
            bv.require(bv.sha(path) == digest, 'Input changed: '+path)


def record_chromium_reference(output, browser, profile):
    bv.write(output/'chromium-integrity.json', dict(
        executable=browser['executable'], sha256=browser['sha256'],
        signature_profile=profile, verification='campaign-start reference; rechecked after profile'))


def verify_chromium_after_profile(browser, profile_root, profile):
    actual = bv.sha(browser['executable'])
    evidence = dict(executable=browser['executable'], expected_sha256=browser['sha256'],
                    actual_sha256=actual, signature_profile=profile,
                    status='PASS' if actual == browser['sha256'] else 'FAIL')
    bv.write(profile_root/'chromium-integrity.json', evidence)
    bv.require(actual == browser['sha256'],
               f'Chromium executable integrity changed during profile={profile}')


def describe(values):
    return dict(n=len(values), minimum=min(values), maximum=max(values), mean=statistics.mean(values),
                median=statistics.median(values), sample_stdev=statistics.stdev(values) if len(values)>1 else None)


def save_outputs(root, summary, rows, pairs, warmup_rows=()):
    for name, fields, data in [('measurements.csv', (*META, *METRICS, *CSV_DECOMPOSITION, *CSV_COMPARISON), rows), ('pairs.csv', PAIR_FIELDS, pairs)]:
        with (root/name).open('x', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore'); writer.writeheader(); writer.writerows(data)
    with (root/'warmups.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=('phase', *META, *METRICS, *CSV_DECOMPOSITION, *CSV_COMPARISON),
                                extrasaction='ignore')
        writer.writeheader(); writer.writerows(warmup_rows)
    summary.update(finished_at=now(), completed_pairs=len(pairs), attempted_runs=len(rows),
                   pass_runs=sum(row['status']=='PASS' for row in rows),
                   failed_or_inconclusive_runs=sum(row['status']!='PASS' for row in rows),
                   attempted_warmup_runs=len(warmup_rows),
                   pass_warmup_runs=sum(row['status']=='PASS' for row in warmup_rows),
                   failed_or_inconclusive_warmup_runs=sum(row['status']!='PASS' for row in warmup_rows),
                   warmup_results=[{key: row.get(key) for key in
                                    ('phase', 'signature_profile', 'case', 'pair_index',
                                     'execution_order', 'status', 'reason', 'result_directory')}
                                   for row in warmup_rows],
                   warmup_policy='Fail closed on first failed warmup; never replace or include warmups in measured statistics',
                   statistics_scope='Complete PASS pairs only', descriptive_statistics={})
    accepted = [row for row in rows if row['pair_complete']]
    if accepted:
        completed_profiles = sorted({row['signature_profile'] for row in accepted})
        summary['descriptive_statistics'] = {profile: {
            case: {metric: describe([row[metric] for row in accepted
                                     if row['signature_profile']==profile and row['case']==case])
                   for metric in METRICS}
            for case in CASES} for profile in completed_profiles}
        comparisons = {
            'mtc-landmark_vs_x509': 'mtc_landmark_vs_x509_delta',
            'mtc-standalone_vs_x509': 'mtc_standalone_vs_x509_delta',
            'mtc-landmark_vs_mtc-standalone':
                'mtc_landmark_vs_mtc_standalone_delta',
        }
        summary['paired_delta_statistics'] = {profile: {
            comparison: {
                metric: describe([pair[metric+'_'+suffix] for pair in pairs
                                  if pair['signature_profile'] == profile])
                for metric in PRIMARY}
            for comparison, suffix in comparisons.items()}
            for profile in completed_profiles}
    summary['decomposition_definitions'] = pcap.DECOMPOSITION_DEFINITIONS
    summary['comparison_definitions'] = pcap.COMPARISON_DEFINITIONS
    summary['handshake_analysis_ok_runs'] = sum(row.get('analysis_status') == 'OK' for row in accepted)
    summary['comparison_statistics'] = {profile: {
        case: {metric: describe(values) for metric in COMPARISON_NUMERIC
               if (values := [row[metric] for row in accepted
                              if row['signature_profile']==profile and row['case']==case
                              and row.get(metric) is not None])}
        for case in CASES} for profile in sorted({row['signature_profile'] for row in accepted})}
    bv.write(root/'summary.json', summary)
    (root/'README.md').write_text(
        '# Chromium paired browser measurement pilot\n\n'
        f"Status: {summary['status']}. Complete pairs: {len(pairs)}/{summary['requested_pairs']}. "
        f"Attempted runs: {len(rows)}; PASS: {summary['pass_runs']}.\n\n"
        f"{summary['tls']['version']} / {summary['key_establishment']} "
        f"(server group {summary['tls']['group']}) / {summary['tls']['cipher']}; "
        f"profiles={', '.join(summary['profiles'])}; "
        f"X.509 D={summary['depth']} (includes root); "
        f"{summary['depth']-1} transmitted certificates; "
        'MTC N=16 landmark and standalone; server-only authentication.\n\n'
        f"Warmups: {summary.get('warmups_per_profile', 0)} complete pairs/profile, retained only in warmups.csv. "
        'Each phase uses the same deterministic three-position rotation: '
        'X.509 / MTC landmark / MTC standalone, rotated once per round. '
        'Each run uses a fresh browser profile and the existing headless PCAP validation. '
        'Credentials and Chromium selection are fixed for the campaign.\n'
        f"X.509 trust mode: {summary.get('x509_trust_mode', 'unspecified')}; "
        f"certificate verification bypass: {str(summary.get('certificate_verification_bypass', False)).lower()}.\n\n"
        'Primary metrics use connections linked by NetLog to the requested navigation. '
        'Secondary metrics include all target TLS connections correlated between PCAP and server.log. '
        +BYTE_DEFINITION+'\n\n'
        'measurements.csv retains every attempted measured run with explicit status; warmups.csv retains warmup evidence. '
        'Warmups are excluded from measurements.csv, pairs.csv and every statistic. '
        'pair_complete identifies rows usable for paired descriptions. pairs.csv contains only complete PASS pairs; '
        'legacy mtc/x509/delta columns retain landmark minus X.509 semantics; '
        'explicit columns provide landmark-X.509, standalone-X.509 and '
        'landmark-standalone comparisons. '
        'summary.json describes only complete PASS pairs. Raw evidence remains in profiles/PROFILE/pair-NNNN/<case>/.\n\n'
        'These are descriptive pilot results, with no bootstrap, hypothesis tests or statistical claims. '
        'There is no network emulation.\n\n'
        '## Optional URL-linked decomposition\n\n'
        'Each field below has a url_linked_ prefix in measurements.csv and additional '
        'scenario and pairwise-delta columns in pairs.csv. Deltas are available only when both values exist. '
        'Existing aggregate metrics are unchanged; these components are not an additive partition.\n\n'
        + '\n'.join('- '+key+': '+value for key, value in pcap.DECOMPOSITION_DEFINITIONS.items())
        + '\n\nUnavailable encrypted components (blank CSV / null JSON): '
        + ', '.join(pcap.DECOMPOSITION[1:6])+'\n\n'
        '## Comparable handshake and browser scope\n\n'
        'measurements.csv appends the shared s_client PCAP schema and separate browser timings. '
        'pairs.csv adds the three pairwise deltas only when both measurements exist. '
        'comparison_statistics reports the available sample count per metric. '
        'Per-stream values are in pair-NNNN/<case>/connection-metrics.csv. '
        'tls.keys contains session secrets (mode 0600); keep it private with the raw evidence.\n\n'
        + '\n'.join('- '+key+': '+value for key, value in pcap.COMPARISON_DEFINITIONS.items())
        + '\n\n' + data_dictionary(summary), encoding='utf-8')
    subprocess.run([
        sys.executable, str(bv.REPO/'bin/renders/chromium.py'),
        str(root/'summary.json'), '--output', str(root/'report.html'),
    ], cwd=bv.REPO, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'requirements', 'status', 'run'))
    parser.add_argument('--pairs', type=int, help='Required for run; no implicit large campaign')
    parser.add_argument('--warmups', type=int, default=0,
                        help='Complete paired warmups per profile, excluded from measured outputs (default: 0)')
    parser.add_argument('--profile', choices=bv.PROFILES, default=bv.PROFILE)
    parser.add_argument('--all-profiles', action='store_true',
                        help=argparse.SUPPRESS)
    parser.add_argument('--key-establishment', choices=tuple(bv.KEY_ESTABLISHMENTS), default='x25519',
                        help='Group restricted at the server and verified in NetLog (default: x25519)')
    parser.add_argument('--depth', type=int, choices=(2, 3, 4, 5), default=2)
    parser.add_argument('--x509-fixture-set')
    parser.add_argument('--chromium', type=Path)
    parser.add_argument('--x509-chromium-ca-policy', action='store_true',
                        help='Use an externally installed Chromium CACertificates policy as the X.509 trust anchor; no certificate bypass')
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--image', default='mt-tls-mtc:local')
    args = parser.parse_args()
    bv.require(args.pairs is None or args.pairs > 0, '--pairs must be a positive integer')
    bv.require(args.warmups >= 0, '--warmups must be a non-negative integer')
    bv.require(not args.x509_fixture_set or args.action == 'run',
               '--x509-fixture-set requires run')
    bv.require(not args.x509_chromium_ca_policy or args.action == 'run',
               '--x509-chromium-ca-policy requires run')
    bv.require(not args.all_profiles or args.action == 'run', '--all-profiles requires run')
    bv.require(5 <= args.timeout <= 300, 'Timeout must be between 5 and 300 seconds')
    if args.action == 'run' and args.x509_fixture_set is None:
        args.x509_fixture_set = FORMAL_X509_FIXTURE_SET
    if args.action == 'plan':
        tls = bv.key_establishment_config(args.key_establishment)
        print(f"PRINT ONLY: {tls['version']} / {tls['key_establishment_label']} (server group {tls['group']}) / "
              f"{tls['cipher']} / {args.profile} / D={args.depth} / MTC N=16 / server-only.")
        print('Chromium keeps its compiled group offer; the server is restricted to the selected group and NetLog checks negotiation.')
        print('Round order rotates deterministically across x509, mtc-landmark and mtc-standalone.')
        print(f'Warmups: {args.warmups} complete pairs/profile; executed first and excluded from measured outputs.')
        print(f"Pairs: {args.pairs if args.pairs is not None else 'explicit --pairs required for run'}")
        print('Each run must PASS existing browser/PCAP validation. Stop on any failure; preserve evidence.')
        print('Outputs: measurements.csv, pairs.csv, summary.json, report.html, README.md and per-run evidence.'); return 0
    if args.action == 'requirements':
        print(bv.json.dumps(pcap.requirements(), indent=2))
        print('tshark is required for measurement metrics. A trusted X.509 root or externally installed Chromium CACertificates policy, plus valid requested-profile/depth fixtures, is required.'); return 0
    if args.action == 'status':
        paths = sorted((bv.REPO/'artifacts/results').glob(PREFIX+'*/summary.json'))
        print(bv.json.dumps(bv.read(paths[-1]), indent=2) if paths else 'NO BROWSER MEASUREMENT RESULTS'); return 0
    bv.require(args.pairs is not None, 'Specify --pairs explicitly, for example run --pairs 3')
    profiles = CAMPAIGN_PROFILES if args.all_profiles else (args.profile,)
    prepared = campaign_preconditions(
        bv.REPO, args.image, profiles, args.depth, args.x509_fixture_set)
    args.x509_chromium_ca_policy = True
    tools = pcap.requirements()
    bv.require(tools['interface'] and (tools['dumpcap'] or tools['tcpdump']) and tools['tshark'],
               'Measurements require Darwin/Linux, dumpcap or tcpdump, and tshark. '+tools['instruction'])
    bv.check_hostname()
    browser = bv.browser_executable(args.chromium)
    chromium_executable = browser['executable']
    with socket.socket() as sock:
        try: sock.bind(('127.0.0.1', 4433))
        except OSError: raise ValueError('Port 4433 occupied; stop its owner explicitly')
    lock = bv.REPO/'.mt-state/chromium-browser-validation.lock'
    lock.parent.mkdir(exist_ok=True)
    try: lock.mkdir()
    except FileExistsError: raise ValueError('Browser validation locked; inspect active run before retrying')
    root = None; rows = []; pairs = []; warmup_rows = []
    totals = campaign_totals(profiles, args.pairs, args.warmups)
    summary = dict(status='FAIL', overall_pass=False, started_at=now(),
                   requested_pairs=totals['total_pairs'], requested_runs=totals['total_measurements'],
                   profiles=list(profiles), key_establishment=args.key_establishment,
                   depth=args.depth, fixture_set=args.x509_fixture_set, **totals,
                   warmups=args.warmups, byte_definition=BYTE_DEFINITION,
                   tls=bv.key_establishment_config(args.key_establishment),
                   x509_trust_mode='chromium-ca-policy', certificate_verification_bypass=False,
                   capture_backend=tools,
                   scenarios=list(CASES),
                   order_policy='Deterministic cyclic rotation by pair index; no random seed')
    try:
        root = bv.REPO/'artifacts/results'/(PREFIX+bv.stamp()); root.mkdir(parents=True, exist_ok=False)
        summary['run_id'] = root.name
        print('Result directory: '+str(root), flush=True)
        summary.update(chromium=browser, credentials={}, x509_policies={}, input_sha256={})
        for profile in profiles:
            credentials, x509_trust_metadata = prepared[profile]
            x509_trust_metadata = dict(x509_trust_metadata,
                fixture_root_pem_sha256=credentials['x509']['root_sha256'])
            profile_root = root/'profiles'/profile; profile_root.mkdir(parents=True)
            bv.write(profile_root/'credentials.json', credentials)
            summary['credentials'][profile] = credentials
            summary['x509_policies'][profile] = x509_trust_metadata
            inputs = {str(Path(data[key])): bv.sha(data[key]) for data, keys in (
                (credentials['mtc_landmark'], ('cert','key','trust','anchor')),
                (credentials['mtc_standalone'], ('cert','key','trust','anchor')),
                (credentials['x509'], ('cert','key','root'))) for key in keys}
            if credentials['x509'].get('intermediates'):
                path = credentials['x509']['intermediates']; inputs[path] = bv.sha(path)
            inputs[browser['executable']] = browser['sha256']
            summary['input_sha256'][profile] = inputs
            for phase, pair_count in campaign_phases(args.warmups, args.pairs):
                phase_rows = warmup_rows if phase == 'warmup' else rows
                phase_root = profile_root/'warmups' if phase == 'warmup' else profile_root
                if pair_count and phase == 'warmup':
                    phase_root.mkdir()
                for pair_index in range(1, pair_count+1):
                    pair_root = phase_root/f'pair-{pair_index:04d}'; pair_root.mkdir()
                    pair_rows = []
                    for position, case in enumerate(order(pair_index), 1):
                        output = pair_root/case
                        run_credentials, validation_case, selected = scenario_credentials(
                            credentials, case)
                        if case in MTC_CASES:
                            bv.CA = selected['ca_id']
                            bv.SELECTED = selected['selected_tai']
                            bv.REQUESTED = selected['requested_tai']
                        relative_output = output.relative_to(root)
                        row = dict(pair=pair_index, pair_index=pair_index,
                                   execution_order=len(warmup_rows)+len(rows)+1,
                                   order_within_pair=position, case=case, signature_profile=profile,
                                   mtc_trust_mode=selected.get('mode', ''),
                                   credential=selected['cert'],
                                   anchor=selected.get('anchor', ''),
                                   requested_tai=selected.get('requested_tai', ''),
                                   selected_tai=selected.get('selected_tai', ''),
                                   key_establishment=args.key_establishment,
                                   key_exchange_group=bv.KEY_ESTABLISHMENTS[args.key_establishment]['openssl_group'],
                                   depth=args.depth, run_id=f'{root.name}/{relative_output}',
                                   timestamp=now(), result_directory=str(output), capture_sha256='',
                                   status='INCONCLUSIVE', pair_complete=False,
                                   fixture=selected['fixture'], reason='')
                        if phase == 'warmup':
                            row['phase'] = phase
                        phase_rows.append(row); pair_rows.append(row)
                        capture = pcap.Capture(output, tools)
                        execution = dict(phase=phase, profile=profile, case=case,
                                         pair_index=pair_index,
                                         execution_order=row['execution_order'])
                        try:
                            verify_measurement_inputs(inputs, chromium_executable)
                            with socket.socket() as sock:
                                try: sock.bind(('127.0.0.1', 4433))
                                except OSError: raise ValueError('Port 4433 occupied; stop its owner explicitly')
                            browser_result = bv.run_case(validation_case, run_credentials,
                                                         browser, output, pair_root, args.timeout,
                                                         False, browser_mode='headless', capture=capture,
                                                         key_establishment=args.key_establishment)
                            browser_result['measurement_scenario'] = case
                            if case == 'x509':
                                browser_result['mtc_trust_mode'] = None
                            bv.write(output/'measurement-metadata.json', execution)
                            record_chromium_reference(output, browser, profile)
                            browser_result['signature_profile'] = profile
                            if case == 'x509': browser_result.update(x509_trust_metadata)
                            bv.write(output/'browser-result.json', browser_result)
                            result = pcap.analyze(output, capture, browser_result)
                            result['measurement_scenario'] = case
                            if case == 'x509': result.update(x509_trust_metadata)
                            bv.write(output/'result.json', result); bv.write(output/'summary.json', result)
                            row.update(status=result['observed_outcome'], capture_sha256=result.get('capture_sha256',''))
                            bv.require(browser_result['pass'] is True and result['pass'] is True
                                       and row['status']=='PASS', 'Individual run is not PASS: '+str(result.get('reasons', [])))
                            wire = result['wire_observed']
                            bv.require(all(type(wire.get(k)) is int and wire[k]>=0 for k in METRICS), 'Missing/invalid integer metrics')
                            row.update({key: wire[key] for key in METRICS})
                            row.update({key: wire.get(key) for key in DECOMPOSITION})
                            row.update({key: wire.get(key) for key in COMPARISON})
                        except BaseException as error:
                            record_measurement_error(output, row, error, phase, execution)
                            raise
                        finally: capture.stop()
                        print(f'{profile} {phase} pair {pair_index}, order {position}, {case}: PASS', flush=True)
                    for row in pair_rows: row['pair_complete'] = True
                    if phase == 'warmup':
                        continue
                    by_case = {row['case']: row for row in pair_rows}
                    paired = dict(pair=pair_index, pair_index=pair_index,
                                  execution_order=' -> '.join(order(pair_index)), signature_profile=profile,
                                  key_establishment=args.key_establishment,
                                  key_exchange_group=bv.KEY_ESTABLISHMENTS[args.key_establishment]['openssl_group'],
                                  depth=args.depth)
                    for metric in (*PRIMARY, *DECOMPOSITION, *COMPARISON_NUMERIC):
                        paired.update(paired_values(by_case, metric))
                    pairs.append(paired)
            verify_chromium_after_profile(browser, profile_root, profile)
        summary.update(status='PASS', overall_pass=True)
        return 0
    except BaseException as error:
        summary['reason'] = str(error) or type(error).__name__
        raise
    finally:
        try:
            if root is not None: save_outputs(root, summary, rows, pairs, warmup_rows)
        finally:
            lock.rmdir()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, bv.subprocess.SubprocessError) as error:
        print('ERROR: '+str(error), file=sys.stderr); sys.exit(1)
