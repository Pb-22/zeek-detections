#!/usr/bin/env python3
"""Replay the bound Modbus collection and publisher selection controls offline."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package_path(root, name):
    if not isinstance(name, str) or not name or '\\' in name or any(x in ('', '.', '..') for x in name.split('/')):
        raise ValueError('Invalid package-relative path')
    path = (root / name).resolve()
    if Path(name).is_absolute() or not path.is_relative_to(root.resolve()):
        raise ValueError('Path escapes package')
    return path


def load_package(root):
    """Authenticate all source, loader and capture inputs before execution."""
    config = json.loads((root / 'modbus-cases.json').read_text(encoding='utf-8'))
    if config['schema_version'] != 1:
        raise ValueError('Unsupported case schema')
    bindings = [(config['loader'], config['loader_sha256']),
                (config['pkinit_script'], config['pkinit_sha256'])]
    bindings += [(m['script'], m['sha256']) for m in config['modules']]
    bindings += [(c['pcap'], c['sha256']) for c in config['captures']]
    for name, expected in bindings:
        if digest(package_path(root, name)) != expected:
            raise ValueError('SHA-256 mismatch: ' + name)
    notes = {m['notice_type'] for m in config['modules']} | {'PKINIT_U2U::Self_Targeted_Ticket'}
    captures = {c['pcap'] for c in config['captures']}
    scripts = {m['script'] for m in config['modules']}
    names = set()
    for case in config['cases']:
        name = case['case']
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]*', name) or name in names:
            raise ValueError('Invalid or duplicate case name')
        names.add(name)
        if set(case['expected']) != notes or any(type(n) is not int or n < 0 for n in case['expected'].values()):
            raise ValueError('Invalid full notice count map')
        if case['selection'] not in {'standalone', 'bundle', 'modbus-disabled', 'all-disabled'}:
            raise ValueError('Invalid selection')
        if case['pcap'] not in captures or (case['selection'] == 'standalone' and case['script'] not in scripts):
            raise ValueError('Unbound case input')
    return config


def json_rows(path):
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError('Expected JSON objects in ' + path.name)
    return rows


def native_modbus(work):
    """Retain protocol fields for private enabled/disabled parity checks."""
    return {path.name: [{k: v for k, v in row.items() if k != 'uid'} for row in json_rows(path)]
            for path in sorted(work.glob('modbus*.log'))}


def run_case(root, config, case, output, zeek):
    work = output / case['case']
    work.mkdir()
    selection = case['selection']
    if selection == 'standalone':
        loader = package_path(root, case['script'])
    elif selection == 'bundle':
        loader = package_path(root, config['loader'])
    else:
        scripts = work / 'scripts'
        shutil.copytree(root / 'scripts', scripts)
        loader = scripts / '__load__.zeek'
        loads = '@load base/protocols/modbus\n'
        if selection == 'modbus-disabled':
            loads += '@load ./pkinit-u2u\n'
        loader.write_text(loads, encoding='utf-8')
    pcap = package_path(root, case['pcap'])
    result = subprocess.run([zeek, '-Cr', str(pcap), str(loader), 'LogAscii::use_json=T'],
                            cwd=work, capture_output=True, text=True, timeout=60)
    (work / 'stdout.txt').write_text(result.stdout, encoding='utf-8')
    (work / 'stderr.txt').write_text(result.stderr, encoding='utf-8')
    rows = json_rows(work / 'notice.log')
    counts = Counter(row.get('note') for row in rows)
    observed = {note: counts.pop(note, 0) for note in case['expected']}
    actions = all(row.get('actions') == ['Notice::ACTION_LOG'] for row in rows)
    suppression = all(row.get('suppress_for') == 0 for row in rows
                      if row.get('note', '').startswith('ModbusWriteRejection::'))
    custom_absent = not (work / 'pkinit_u2u.log').exists()
    errors = sum(row.get('level') == 'ERROR' for row in json_rows(work / 'reporter.log'))
    fields_valid = True
    reasons = {m['notice_type']: m['reason'] for m in config['modules']}
    for row in rows:
        if row.get('note') not in reasons:
            continue
        fields = dict(re.findall(r'(\w+)=(\d+)', row.get('sub', '')))
        fields_valid &= (set(fields) == {'transaction_id', 'unit_id', 'function_code',
                                          'exception_code', 'protocol_id', 'mbap_length'}
                         and fields.get('exception_code') == str(reasons[row['note']])
                         and fields.get('protocol_id') == '0' and fields.get('mbap_length') == '3'
                         and fields.get('function_code') in {'6', '16'}
                         and 'uid' in row and 'id.orig_h' in row and 'id.resp_h' in row)
    passed = (result.returncode == 0 and not result.stdout and not result.stderr and errors == 0
              and observed == case['expected'] and not counts and actions and suppression
              and custom_absent and fields_valid)
    return {'case': case['case'], 'selection': selection, 'pcap_sha256': digest(pcap),
            'executed_loader_sha256': digest(loader), 'expected': case['expected'], 'observed': observed,
            'unexpected_notice_count': sum(counts.values()), 'notice_actions_log_only': actions,
            'zero_suppression': suppression, 'notice_fields_valid': bool(fields_valid),
            'custom_log_absent': custom_absent, 'exit_code': result.returncode,
            'stdout_empty': not result.stdout, 'stderr_empty': not result.stderr,
            'reporter_error_count': errors, 'passed': bool(passed)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zeek', default='zeek', help='Local Zeek executable; collection tested on 9.0.0 and 9.0.1')
    parser.add_argument('--output', type=Path, required=True, help='New directory outside the checkout for private logs and a sanitized receipt')
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent
    output = args.output.resolve()
    try:
        if output.exists() or output.is_relative_to(root):
            raise ValueError('Output must be a new directory outside the checkout')
        config = load_package(root)
        version = subprocess.run([args.zeek, '--version'], capture_output=True, text=True, timeout=15, check=True)
        zeek_version = version.stdout.strip() or version.stderr.strip()
        if not zeek_version:
            raise ValueError('Zeek returned no version')
        output.mkdir(parents=True, exist_ok=False)
        rows = [run_case(root, config, case, output, args.zeek) for case in config['cases']]
        parity = True
        for module in config['modules']:
            key = str(module['reason'])
            enabled = native_modbus(output / ('bundle-' + key))
            disabled = native_modbus(output / ('modbus-disabled-' + key))
            standalone = native_modbus(output / ('standalone-' + key))
            parity &= bool(enabled.get('modbus.log')) and enabled == disabled == standalone
        receipt = {'schema_version': 1, 'output_contract': 'notice-only', 'zeek_version': zeek_version,
                   'source_commit': config['source_commit'], 'loader_sha256': config['loader_sha256'],
                   'pkinit_sha256': config['pkinit_sha256'],
                   'module_sha256': {m['script']: m['sha256'] for m in config['modules']},
                   'cases_manifest_sha256': digest(root / 'modbus-cases.json'),
                   'runner_sha256': digest(Path(__file__).resolve()), 'cases': rows,
                   'native_modbus_logs_preserved': bool(parity),
                   'passed': bool(rows) and all(row['passed'] for row in rows) and bool(parity)}
        text = json.dumps(receipt, indent=2) + '\n'
        (output / 'receipt.json').write_text(text, encoding='utf-8')
        print(text, end='')
        return 0 if receipt['passed'] else 1
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('Replay failed: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
