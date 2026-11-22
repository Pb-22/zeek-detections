"""Modbus release bindings and native package integration."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PKINIT = 'PKINIT_U2U::Self_Targeted_Ticket'
NAMES = ['Illegal_Function', 'Illegal_Data_Address', 'Illegal_Data_Value', 'Server_Device_Failure']
NOTES = ['ModbusWriteRejection::Register_Write_' + name for name in NAMES]
HASHES = ['0de1f7dfc921292c1e90a75514cc6a58ade774d768ab7cf9b3143371253c2fbb',
          '6fbbf3254a46c3af160189a8f96720f71f247a177089a5f48816f82d9ac3e54a',
          'ff343f54fd21192e380d08a7161ea989ca2c5e30cc8bdbae0055135846c92e5b',
          '8d35a1479a789cb9a5c37155c0a1d03b6bc7c8e36b33ac4d68ab4fbfb7ce5bf3']

class ModbusTests(unittest.TestCase):
    def runner(self):
        self.assertTrue((ROOT/'modbus_replay.py').is_file(), 'portable Modbus runner must exist')
        spec = importlib.util.spec_from_file_location('modbus_replay', ROOT/'modbus_replay.py')
        assert spec is not None and spec.loader is not None
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        return runner

    def test_selected_modules_and_explicit_profiles(self):
        config = self.runner().load_package(ROOT)
        self.assertEqual([m['notice_type'] for m in config['modules']], NOTES)
        self.assertEqual([m['sha256'] for m in config['modules']], HASHES)
        self.assertEqual(len(config['cases']), 15)
        for i, case in enumerate(c for c in config['cases'] if c['selection'] == 'bundle' and c['case'].startswith('bundle-')):
            self.assertEqual(case['expected'], dict(zip(NOTES + [PKINIT],
                ([2,2,1,0,0] if i < 2 else [2,2,2,2,0]))))
        for i, case in enumerate(c for c in config['cases'] if c['selection'] == 'standalone'):
            expected = dict.fromkeys(NOTES + [PKINIT], 0)
            expected[NOTES[i]] = 2
            self.assertEqual(case['expected'], expected)
        for case in config['cases']:
            if case['selection'] in {'modbus-disabled', 'all-disabled'}:
                self.assertEqual(case['expected'], dict.fromkeys(NOTES + [PKINIT], 0))

    def test_sanitized_receipts_bind_current_inputs(self):
        config = self.runner().load_package(ROOT)
        for version in ('9.0.0', '9.0.1'):
            path = ROOT/('modbus-validation-' + version + '.json')
            self.assertTrue(path.is_file(), 'actual Modbus receipt must exist')
            receipt = json.loads(path.read_text())
            self.assertEqual(receipt['zeek_version'], 'zeek version ' + version)
            self.assertTrue(receipt['passed'])
            self.assertTrue(receipt['native_modbus_logs_preserved'])
            for name, key in [('modbus_replay.py', 'runner_sha256'),
                              ('modbus-cases.json', 'cases_manifest_sha256'),
                              ('scripts/__load__.zeek', 'loader_sha256'),
                              ('scripts/pkinit-u2u.zeek', 'pkinit_sha256')]:
                self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(), receipt[key])
            self.assertEqual(receipt['module_sha256'], {m['script']: m['sha256'] for m in config['modules']})
            self.assertEqual(len(receipt['cases']), 15)
            self.assertEqual({r['case'] for r in receipt['cases']}, {c['case'] for c in config['cases']})
            for case, row in zip(config['cases'], receipt['cases']):
                self.assertEqual(row['expected'], case['expected'])
                self.assertEqual(row['observed'], case['expected'])
                self.assertTrue(row['passed'])
            for forbidden in ['/home/', '/mnt/', 'transaction_id=', 'uid"']:
                self.assertNotIn(forbidden, path.read_text())

    def test_bound_inputs_reject_mutations(self):
        runner = self.runner()
        config = runner.load_package(ROOT)
        paths = [config['loader'], config['modules'][0]['script'], config['captures'][0]['pcap'],
                 'scripts/pkinit-u2u.zeek']
        for name in paths:
            with self.subTest(path=name), tempfile.TemporaryDirectory() as directory:
                dest = Path(directory)/'package'
                shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns('.git'))
                with (dest/name).open('ab') as stream: stream.write(b'\n')
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    runner.load_package(dest)

    def test_invalid_count_maps_rejected(self):
        runner = self.runner()
        for mutate in ('missing', 'bool'):
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as directory:
                dest = Path(directory)/'package'
                shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns('.git'))
                path = dest/'modbus-cases.json'
                config = json.loads(path.read_text())
                if mutate == 'missing': config['cases'][0]['expected'].pop(PKINIT)
                else: config['cases'][0]['expected'][PKINIT] = False
                path.write_text(json.dumps(config))
                with self.assertRaisesRegex(ValueError, 'count map'):
                    runner.load_package(dest)

    def test_cli_refuses_existing_or_checkout_output(self):
        for output in (ROOT, ROOT/'forbidden-modbus-output'):
            result = subprocess.run([sys.executable, '-I', str(ROOT/'modbus_replay.py'),
                '--output', str(output)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Output', result.stderr)
            self.assertFalse((ROOT/'forbidden-modbus-output').exists())

    def test_cli_help_and_missing_engine(self):
        help_result = subprocess.run([sys.executable, '-I', str(ROOT/'modbus_replay.py'), '--help'],
                                     capture_output=True, text=True)
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn('--output', help_result.stdout)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'result'
            result = subprocess.run([sys.executable, '-I', str(ROOT/'modbus_replay.py'),
                '--zeek', str(Path(directory)/'absent'), '--output', str(output)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((output/'receipt.json').exists())

    def test_native_standalone_bundle_and_disabled_selection(self):
        engine = os.environ.get('ZEEK_BIN') or 'zeek'
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'replay'
            result = subprocess.run([sys.executable, '-B', str(ROOT/'modbus_replay.py'),
                '--zeek', engine, '--output', str(output)], capture_output=True, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            receipt = json.loads((output/'receipt.json').read_text())
            self.assertTrue(receipt['passed'])
            self.assertEqual(len(receipt['cases']), 15)
            self.assertTrue(receipt['native_modbus_logs_preserved'])
            self.assertEqual(receipt['runner_sha256'], hashlib.sha256((ROOT/'modbus_replay.py').read_bytes()).hexdigest())
            for row in receipt['cases']:
                self.assertEqual(row['expected'], row['observed'])
                self.assertTrue(row['passed'])
                self.assertTrue(row['notice_actions_log_only'])
                self.assertTrue(row['zero_suppression'])
                self.assertTrue(row['custom_log_absent'])
            for forbidden in ['/home/', '/mnt/', 'transaction_id=', 'uid"']:
                self.assertNotIn(forbidden, json.dumps(receipt))

if __name__ == '__main__': unittest.main()
