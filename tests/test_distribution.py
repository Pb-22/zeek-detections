"""Package selection and real Zeek loader acceptance."""
import configparser
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class DistributionTests(unittest.TestCase):
    def test_metadata_and_selected_runtime_are_explicit(self):
        self.assertTrue((ROOT/'zkg.meta').is_file(), 'zkg metadata must exist')
        config = configparser.ConfigParser()
        config.read(ROOT/'zkg.meta')
        self.assertEqual(config['package']['script_dir'], 'scripts')
        self.assertEqual(config['package']['depends'], 'zeek >=9.0')
        self.assertEqual(config['package']['version'], '1.1.0')
        loads = [line.strip() for line in (ROOT/'scripts/__load__.zeek').read_text().splitlines()
                 if line.strip().startswith('@load ')]
        modules = ['pkinit-u2u', 'modbus-write-illegal-function',
                   'modbus-write-illegal-data-address', 'modbus-write-illegal-data-value',
                   'modbus-write-server-device-failure']
        self.assertEqual(loads, ['@load ./' + name for name in modules])
        self.assertEqual({p.name for p in (ROOT/'scripts').iterdir()},
                         {'__load__.zeek'} | {name + '.zeek' for name in modules})
        self.assertEqual(hashlib.sha256((ROOT/'scripts/pkinit-u2u.zeek').read_bytes()).hexdigest(),
                         '1e2a74def6eb7f630a2739b5eea1bab56aad17d8e0d916f4f7f5e085f7902126')
        self.assertTrue((ROOT/'tests/fixtures/event-regressions.zeek').is_file())
        self.assertNotIn('regression_case', (ROOT/'scripts/__load__.zeek').read_text())

    def test_publisher_enable_and_disable_through_real_loader(self):
        engine = os.environ.get('ZEEK_BIN') or shutil.which('zeek')
        self.assertTrue(engine, 'Zeek is required for package acceptance')
        assert engine is not None
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            scripts = temp/'scripts'
            self.assertTrue((ROOT/'scripts/__load__.zeek').is_file(), 'Publisher loader must exist')
            shutil.copytree(ROOT/'scripts', scripts)
            for enabled, expected in [(True, 1), (False, 0)]:
                if not enabled:
                    (scripts/'__load__.zeek').write_text('# No publisher-enabled modules.\n')
                output = temp/str(enabled)
                output.mkdir()
                result = subprocess.run([engine, '-Cr', str(ROOT/'pcap/positive-pkinit-u2u.pcap'),
                    str(scripts/'__load__.zeek'), 'LogAscii::use_json=T'],
                    cwd=output, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, '')
                self.assertFalse((output/'pkinit_u2u.log').exists())
                path = output/'notice.log'
                notices = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
                self.assertEqual(sum(row.get('note') == 'PKINIT_U2U::Self_Targeted_Ticket'
                                     for row in notices), expected)

    def test_all_capture_and_constructed_cases_on_real_engine(self):
        engine = os.environ.get('ZEEK_BIN') or shutil.which('zeek')
        self.assertTrue(engine, 'Zeek is required for package acceptance')
        assert engine is not None
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'replay'
            result = subprocess.run(['python3', '-B', str(ROOT/'replay.py'), '--zeek', engine,
                '--events', '--output', str(output)], capture_output=True, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads((output/'receipt.json').read_text())
            self.assertTrue(receipt['passed'])
            self.assertEqual(receipt['schema_version'], 2)
            self.assertEqual(receipt['output_contract'], 'notice-only')
            self.assertEqual(len(receipt['cases']), 39)
            self.assertTrue(all(row['custom_log_absent'] for row in receipt['cases']))

if __name__ == '__main__':
    unittest.main()
