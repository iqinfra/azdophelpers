"""Execute the complete launcher with verified synthetic helper downloads."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

class LauncherTests(unittest.TestCase):
    def run_case(self, status=0, corrupt=False, download_fail=False):
        with tempfile.TemporaryDirectory(prefix='launcher test ') as directory:
            root = Path(directory)
            temp = root / 'temp space'
            temp.mkdir()
            bin_dir = root / 'bin'
            bin_dir.mkdir()
            diff = '''#!/usr/bin/env bash
set -eu
[[ ${SYSTEM_ACCESSTOKEN:-} == synthetic-devops-secret ]]
[[ ! -v AZURE_OPENAI_API_KEY && ! -v AZURE_KEY && ! -v TFVC_TOKEN && ! -v OPENAI_API_KEY && ! -v CODEX_API_KEY ]]
printf 'diff helper completed\\n'
'''
            review = f'''#!/usr/bin/env bash
set -eu
[[ $AZURE_OPENAI_API_KEY == synthetic-azure-secret ]]
[[ $HELPER_COMMIT == {'a' * 40} ]]
[[ $CODEX_REASONING_EFFORT == max ]]
[[ ! -v SYSTEM_ACCESSTOKEN && ! -v AZURE_KEY && ! -v TFVC_TOKEN && ! -v OPENAI_API_KEY && ! -v CODEX_API_KEY ]]
printf 'review helper completed\\n'
exit {status}
'''
            (root / 'diff').write_text(diff)
            (root / 'review').write_text(review)
            source = (ROOT / 'azure-devops-launcher.sh').read_text()
            for key, value in [('HELPER_COMMIT', 'a'*40), ('DIFF_HELPER_SHA256', hashlib.sha256(diff.encode()).hexdigest()), ('CODEX_HELPER_SHA256', hashlib.sha256(review.encode()).hexdigest())]:
                source = re.sub(r'readonly '+key+r'="[^"]*"', f'readonly {key}="{value}"', source)
            script = root / 'launcher.sh'
            script.write_text(source)
            curl = bin_dir / 'curl'
            curl.write_text('''#!/usr/bin/env python3
import os, pathlib, sys
assert not any(k in os.environ for k in ['SYSTEM_ACCESSTOKEN','AZURE_KEY','TFVC_TOKEN','AZURE_OPENAI_API_KEY','OPENAI_API_KEY','CODEX_API_KEY'])
if os.environ['DOWNLOAD_FAIL']=='1': sys.exit(22)
root=pathlib.Path(os.environ['FIXTURE_ROOT'])
content=(root/('diff' if 'generate-changeset-diff.sh' in sys.argv[-1] else 'review')).read_bytes()
if os.environ['CORRUPT']=='1': content+=b'corruption'
pathlib.Path(sys.argv[sys.argv.index('--output')+1]).write_bytes(content)
''')
            curl.chmod(0o700)
            env = dict(os.environ, PATH=str(bin_dir)+os.pathsep+os.environ['PATH'],
                       FIXTURE_ROOT=str(root), CORRUPT=str(int(corrupt)), DOWNLOAD_FAIL=str(int(download_fail)),
                       AGENT_TEMPDIRECTORY=str(temp), SYSTEM_ACCESSTOKEN='synthetic-devops-secret',
                       AZURE_OPENAI_API_KEY='synthetic-azure-secret', AZURE_KEY='inherited', TFVC_TOKEN='inherited',
                       OPENAI_API_KEY='inherited', CODEX_API_KEY='inherited', CODEX_REASONING_EFFORT='max',
                       AZURE_OPENAI_BASE_URL='https://example.openai.azure.com/openai/v1', AZURE_OPENAI_MODEL_DEPLOYMENT='existing')
            result = subprocess.run(['bash', str(script)], env=env, text=True, capture_output=True)
            self.assertEqual(list(temp.iterdir()), [])
            self.assertNotIn('synthetic-azure-secret', result.stdout+result.stderr)
            self.assertNotIn('synthetic-devops-secret', result.stdout+result.stderr)
            return result

    def test_success_and_key_scope(self):
        result=self.run_case()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('review helper completed',result.stdout)

    def test_expected_security_block(self):
        result=self.run_case(2)
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn('security gate blocked',result.stdout)
        self.assertNotIn('unexpectedly',result.stdout)

    def test_operational_failure(self):
        result=self.run_case(1)
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertNotIn('unexpectedly',result.stdout)

    def test_corrupt_download(self):
        result=self.run_case(corrupt=True)
        self.assertEqual(result.returncode,1)
        self.assertIn('SHA-256 verification failed',result.stdout)
        self.assertNotIn('diff helper completed',result.stdout)

    def test_failed_download(self):
        result=self.run_case(download_fail=True)
        self.assertEqual(result.returncode,1)
        self.assertIn('Helper download failed',result.stdout)

if __name__ == '__main__':
    unittest.main()
