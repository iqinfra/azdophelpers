"""Failure-boundary regressions, including build cancellation cleanup."""
import os
from pathlib import Path
import signal
import subprocess
import time
import unittest

from test_pipeline import PipelineCase, MOCK_CODEX, HELPER, ROOT, CHANGESET

class PipelineEdgeTests(unittest.TestCase):
    def setUp(self):
        self.h = PipelineCase('pass')
    def tearDown(self):
        self.h.close()
    def assert_failed_before_report(self,result):
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertNotIn('artifact.upload',result.stdout)
        self.assertEqual(self.h.outputs(),set())
        self.assertEqual(list(self.h.agent_tmp.iterdir()),[])
    def test_diff_manifest_mismatch_stops_before_model(self):
        (self.h.artifacts/f'tfvc-changeset-{CHANGESET}.diff').write_text('truncated\n')
        r=self.h.run();self.assert_failed_before_report(r)
        self.assertIn('Diff size or line count',r.stdout)
        self.assertEqual(self.h.state_records(),[])
    def test_multiple_json_documents_rejected(self):
        original='candidate.write_text(json.dumps(review), encoding="utf-8")'
        self.assertIn(original,MOCK_CODEX)
        self.h._write_executable('codex',MOCK_CODEX.replace(original,'candidate.write_text(json.dumps(review)+"\\n"+json.dumps(review), encoding="utf-8")'))
        r=self.h.run();self.assert_failed_before_report(r)
        self.assertIn('schema/semantic validation',r.stdout)
    def test_bad_commit_rejected(self):
        env=self.h.env();env['HELPER_COMMIT']='main'
        r=subprocess.run(['bash',str(HELPER)],env=env,cwd=ROOT,capture_output=True,text=True)
        self.assert_failed_before_report(r)
        self.assertIn('40-character',r.stdout)
    def test_signal_cleans_private_workspaces(self):
        ready=self.h.root/'ready'
        mock='''#!/usr/bin/env python3
import os,pathlib,sys,time
if '--version' in sys.argv:
 print('codex-cli 0.153.4');raise SystemExit(0)
pathlib.Path(os.environ['SIGNAL_READY']).write_text('ready')
time.sleep(20)
'''
        self.h._write_executable('codex',mock)
        env=self.h.env();env['SIGNAL_READY']=str(ready)
        p=subprocess.Popen(['bash',str(HELPER)],env=env,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        try:
            deadline=time.monotonic()+6
            while not ready.exists() and p.poll() is None and time.monotonic()<deadline:
                time.sleep(0.05)
            self.assertTrue(ready.exists(),'mock analysis did not start')
            os.killpg(p.pid,signal.SIGTERM)
            out,err=p.communicate(timeout=6)
            self.assertNotEqual(p.returncode,0)
            self.assertNotIn('artifact.upload',out)
            self.assertNotIn('fake-secret',out+err)
            self.assertEqual(list(self.h.agent_tmp.iterdir()),[])
        finally:
            if p.poll() is None:
                os.killpg(p.pid,signal.SIGKILL);p.communicate()

if __name__=='__main__':unittest.main()
