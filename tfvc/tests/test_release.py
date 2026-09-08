"""Check release pins against committed bytes without contacting GitHub."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

class ReleaseTests(unittest.TestCase):
    def test_missing_diff_helper_is_actionable_and_atomic(self):
        with tempfile.TemporaryDirectory(prefix='release test ') as directory:
            root=Path(directory)
            deliverable=root/'deliverable'; deliverable.mkdir()
            shutil.copytree(ROOT/'tfvc',deliverable/'tfvc',ignore=shutil.ignore_patterns('__pycache__'))
            for name in ['prepare-release.py','azure-devops-launcher.sh']:
                shutil.copy2(ROOT/name,deliverable/name)
            tool=deliverable/'prepare-release.py'
            def run(*args):
                return subprocess.run([sys.executable,str(tool),*map(str,args)],capture_output=True,text=True)

            initial=run(); self.assertEqual(initial.returncode,0,initial.stderr)
            protected = [
                deliverable/'tfvc/run-codex-review.sh',
                deliverable/'run-codex-review.sh',
                deliverable/'azure-devops-launcher.sh',
                deliverable/'package-sha256.txt',
            ]
            before = {path: path.read_bytes() for path in protected}

            repo=root/'repo'; repo.mkdir()
            shutil.copytree(deliverable/'tfvc',repo/'tfvc')
            env=dict(os.environ,GIT_CONFIG_NOSYSTEM='1')
            def git(*args):
                return subprocess.check_output(['git','-C',str(repo),*args],env=env,stderr=subprocess.DEVNULL,text=True).strip()
            git('init','-q');git('add','tfvc')
            git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-qm','fixture without diff helper')
            commit=git('rev-parse','HEAD')

            result=run('--repo',repo,'--commit',commit)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('missing required file tfvc/generate-changeset-diff.sh',result.stderr)
            self.assertNotIn('Traceback',result.stderr)
            self.assertEqual(before, {path: path.read_bytes() for path in protected})

    def test_invalid_repo_and_commit_are_actionable(self):
        with tempfile.TemporaryDirectory(prefix='release test ') as directory:
            root=Path(directory)
            deliverable=root/'deliverable'; deliverable.mkdir()
            shutil.copytree(ROOT/'tfvc',deliverable/'tfvc',ignore=shutil.ignore_patterns('__pycache__'))
            for name in ['prepare-release.py','azure-devops-launcher.sh']:
                shutil.copy2(ROOT/name,deliverable/name)
            tool=deliverable/'prepare-release.py'
            def run(*args):
                return subprocess.run([sys.executable,str(tool),*map(str,args)],capture_output=True,text=True)

            initial=run(); self.assertEqual(initial.returncode,0,initial.stderr)
            protected = [
                deliverable/'tfvc/run-codex-review.sh',
                deliverable/'run-codex-review.sh',
                deliverable/'azure-devops-launcher.sh',
                deliverable/'package-sha256.txt',
            ]
            before = {path: path.read_bytes() for path in protected}
            commit='a'*40

            invalid_repo=run('--repo',root/'missing-repo','--commit',commit)
            self.assertNotEqual(invalid_repo.returncode,0)
            self.assertIn('--repo is not a Git repository',invalid_repo.stderr)
            self.assertNotIn('Traceback',invalid_repo.stderr)
            self.assertEqual(before, {path: path.read_bytes() for path in protected})

            repo=root/'repo'; repo.mkdir()
            shutil.copytree(deliverable/'tfvc',repo/'tfvc')
            (repo/'tfvc/generate-changeset-diff.sh').write_text('#!/bin/bash\nexit 0\n')
            env=dict(os.environ,GIT_CONFIG_NOSYSTEM='1')
            def git(*args):
                return subprocess.check_output(['git','-C',str(repo),*args],env=env,stderr=subprocess.DEVNULL,text=True).strip()
            git('init','-q');git('add','tfvc')
            git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-qm','fixture package')

            absent_commit=run('--repo',repo,'--commit',commit)
            self.assertNotEqual(absent_commit.returncode,0)
            self.assertIn(f'Commit {commit} was not found in --repo',absent_commit.stderr)
            self.assertNotIn('Traceback',absent_commit.stderr)
            self.assertEqual(before, {path: path.read_bytes() for path in protected})

    def test_finder_metadata_is_excluded_but_other_dotfiles_are_verified(self):
        with tempfile.TemporaryDirectory(prefix='release metadata test ') as directory:
            root = Path(directory)
            deliverable = root / 'deliverable'
            deliverable.mkdir()
            shutil.copytree(ROOT / 'tfvc', deliverable / 'tfvc',
                            ignore=shutil.ignore_patterns('__pycache__', '.DS_Store'))
            for name in ('prepare-release.py', 'azure-devops-launcher.sh'):
                shutil.copy2(ROOT / name, deliverable / name)
            legitimate = deliverable / 'tfvc/skills/security-review-html/.release-data'
            legitimate.write_text('legitimate pinned resource')
            def run(*args):
                return subprocess.run([sys.executable, str(deliverable / 'prepare-release.py'),
                                       *map(str, args)], capture_output=True, text=True)
            initial = run()
            self.assertEqual(initial.returncode, 0, initial.stderr)
            repo = root / 'repo'
            shutil.copytree(deliverable / 'tfvc', repo / 'tfvc')
            (repo / 'tfvc/generate-changeset-diff.sh').write_text('#!/bin/bash\nexit 0\n')
            env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1')
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], env=env,
                                               stderr=subprocess.DEVNULL, text=True).strip()
            git('init', '-q')
            git('add', 'tfvc')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-qm', 'clean package')
            commit = git('rev-parse', 'HEAD')
            # Finder can create metadata after the clean package was committed.
            for folder in ('schemas', 'scripts', 'skills', 'skills/security-review-html',
                           'skills/security-review-html/references'):
                (deliverable / 'tfvc' / folder / '.DS_Store').write_bytes(b'finder metadata')
            bound = run('--repo', repo, '--commit', commit)
            self.assertEqual(bound.returncode, 0, bound.stderr)
            for name in ('tfvc/run-codex-review.sh', 'run-codex-review.sh', 'package-sha256.txt'):
                contents = (deliverable / name).read_text()
                self.assertNotIn('.DS_Store', contents)
                self.assertIn('.release-data', contents)
            self.assertIn(commit, (deliverable / 'azure-devops-launcher.sh').read_text())
            legitimate.write_text('changed legitimate resource')
            rejected = run('--repo', repo, '--commit', commit)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('Committed package differs', rejected.stderr)
            self.assertIn('.release-data', rejected.stderr)

    def test_commit_binding_rejects_changed_resources(self):
        with tempfile.TemporaryDirectory(prefix='release test ') as directory:
            root=Path(directory)
            deliverable=root/'deliverable'; deliverable.mkdir()
            shutil.copytree(ROOT/'tfvc',deliverable/'tfvc',ignore=shutil.ignore_patterns('__pycache__'))
            for name in ['prepare-release.py','azure-devops-launcher.sh']:
                shutil.copy2(ROOT/name,deliverable/name)
            tool=deliverable/'prepare-release.py'
            def run(*args):
                return subprocess.run([sys.executable,str(tool),*map(str,args)],capture_output=True,text=True)
            initial=run(); self.assertEqual(initial.returncode,0,initial.stderr)
            self.assertIn('REPLACE_WITH_VERIFIED_PACKAGE_COMMIT',(deliverable/'azure-devops-launcher.sh').read_text())
            repo=root/'repo';repo.mkdir()
            shutil.copytree(deliverable/'tfvc',repo/'tfvc')
            (repo/'tfvc/generate-changeset-diff.sh').write_text('#!/bin/bash\nexit 0\n')
            env=dict(os.environ,GIT_CONFIG_NOSYSTEM='1')
            def git(*args):
                return subprocess.check_output(['git','-C',str(repo),*args],env=env,stderr=subprocess.DEVNULL,text=True).strip()
            git('init','-q');git('add','tfvc')
            git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-qm','fixture package')
            commit=git('rev-parse','HEAD')
            bound=run('--repo',repo,'--commit',commit);self.assertEqual(bound.returncode,0,bound.stderr)
            launcher=(deliverable/'azure-devops-launcher.sh').read_text()
            self.assertIn(commit,launcher)
            self.assertIn(hashlib.sha256((repo/'tfvc/run-codex-review.sh').read_bytes()).hexdigest(),launcher)
            resource=deliverable/'tfvc/requirements.txt';resource.write_text(resource.read_text()+'\n')
            bad=run('--repo',repo,'--commit',commit)
            self.assertNotEqual(bad.returncode,0)
            self.assertIn('Committed package differs',bad.stderr)

if __name__=='__main__':unittest.main()
