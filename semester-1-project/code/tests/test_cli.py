"""End-to-end checks against a local website fixture, with no external target."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[2]
MODULES = ('test_01_secrets', 'test_02_frontend_libs', 'test_03_cookies', 'test_05_security_headers', 'test_08_cors')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(403 if self.path == '/blocked' else 200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Set-Cookie', 'sessionid=fixture; Path=/')
        self.end_headers()
        self.wfile.write(b'<html><head><title>Local test</title></head><body><script>/*! jQuery v3.3.1 */</script>Scanner integration fixture.</body></html>')

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def scan(self, directory, *args, path='/'):
        output = Path(directory) / 'scan.json'
        env = dict(os.environ, BRAVO6_VALIDATION_ALLOW_PRIVATE_TARGETS='1', CVE_TABLE_ENDPOINT='https://unused.invalid')
        proc = subprocess.run([sys.executable, str(ROOT/'code/main_scanner.py'), '--url', f'http://127.0.0.1:{self.server.server_port}{path}', '--output', str(output), *args], cwd=directory, env=env, capture_output=True, text=True, timeout=90)
        return proc, output

    def test_json_only_and_local_database(self):
        with tempfile.TemporaryDirectory() as directory:
            proc, output = self.scan(directory)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads(output.read_text())
            self.assertEqual(set(result['tests']), set(MODULES))
            self.assertEqual(result['tests_run'], 5)
            self.assertIn('CVE-', json.dumps(result['tests']['test_02_frontend_libs']['findings']))
            self.assertFalse(output.with_suffix('.html').exists())

    def test_html_and_json(self):
        with tempfile.TemporaryDirectory() as directory:
            proc, output = self.scan(directory, '--html')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(output.exists())
            html = output.with_suffix('.html').read_text()
            for title in ['Secrets', 'Frontend Libraries', 'Cookies', 'Security Headers', 'CORS']:
                self.assertIn(f'<h2>{title}</h2>', html)
            self.assertEqual(html.count('<h2>'), 5)

    def test_blocked_page_still_saves_both(self):
        with tempfile.TemporaryDirectory() as directory:
            proc, output = self.scan(directory, '--html', path='/blocked')
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertEqual(json.loads(output.read_text())['tests_run'], 0)
            self.assertIn('did not complete', output.with_suffix('.html').read_text())

    def test_report_escapes_target_content_and_filters_modules(self):
        spec = importlib.util.spec_from_file_location('html_report', ROOT/'report/html_report.py')
        report = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(report)
        payload = '<script>alert("test")</script>'
        result = {'url': payload, 'tests': {MODULES[0]: {'status': 'complete', 'findings': [{'title': payload, 'evidence': payload}]}, 'other': {'findings': [{'title': 'UNRELATED FINDING'}]}}}
        html = report.render_report(result, (*MODULES, 'other'))
        self.assertNotIn(payload, html)
        self.assertIn('&lt;script&gt;', html)
        self.assertNotIn('UNRELATED FINDING', html)

    def test_default_results_directory_and_optional_report(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / 'project'
            shutil.copytree(ROOT, project, ignore=shutil.ignore_patterns('__pycache__'))
            shutil.rmtree(project / 'report')
            env = dict(os.environ, BRAVO6_VALIDATION_ALLOW_PRIVATE_TARGETS='1')
            command = [sys.executable, str(project/'code/main_scanner.py'), '--url', f'http://127.0.0.1:{self.server.server_port}/']
            proc = subprocess.run(command, cwd=directory, env=env, capture_output=True, text=True, timeout=90)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(len(list((project/'results').glob('*.json'))), 1)
            self.assertEqual(len(list((project/'results').glob('*.html'))), 0)
            proc = subprocess.run([*command, '--html'], cwd=directory, env=env, capture_output=True, text=True, timeout=90)
            self.assertEqual(proc.returncode, 1)
            self.assertIn('JSON saved, but HTML report failed', proc.stderr)
            self.assertEqual(len(list((project/'results').glob('*.json'))), 2)

    def test_invalid_output_extension_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            proc, output = self.scan(directory, '--output', str(Path(directory)/'scan.html'), '--html')
            self.assertEqual(proc.returncode, 2)
            self.assertIn('must end with .json', proc.stderr)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
