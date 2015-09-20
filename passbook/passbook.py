from subprocess import call
from hashlib import sha1
from uuid import uuid4
import tempfile

import zipfile
import shutil
import json
import sys
import os


class Pass:
    def __init__(self, files, data, cert, key, wwdr, password):
        self.files = set(files)
        self.data = data
        self.cert = cert
        self.key = key
        self.wwdr = wwdr
        self.password = password

        self._make_pass()
        self._make_manifest()
        self._make_signature()

    def _make_manifest(self):
        self.manifest_file = '/tmp/manifest'
        manifest = {}

        for file_name in self.files:
            with open(file_name, 'rb') as f:
                manifest[os.path.basename(file_name)] = sha1(f.read()).hexdigest()

        with open(self.pass_file, 'rb') as f:
            manifest['pass.json'] = sha1(f.read()).hexdigest()

        with open(self.manifest_file, 'w') as f:
            f.write(json.dumps(manifest, indent=4))

    def _make_signature(self):
        self.signature_file = '/tmp/signature'

        command = [
            'openssl', 'smime',
            '-binary', '-sign',
            '-certfile', self.wwdr,
            '-signer', self.cert,
            '-inkey', self.key,
            '-in', self.manifest_file,
            '-out', self.signature_file,
            '-outform', 'DER',
            '-passin', 'pass:' + self.password,
        ]

        self._cmd(command)

    def _make_pass(self):
        self.pass_file = '/tmp/pass'

        with open(self.pass_file, 'w') as f:
            f.write(json.dumps(self.data, indent=4))

    def _cmd(self, params):
        try:
            # Hotfix for this issue:
            # https://github.com/GrahamDumpleton/mod_wsgi/issues/85
            call(params, stdout=sys.stdout, stderr=sys.stderr)
        except AttributeError:
            pass

    def check_signature(self, manifest=None, signature=None):
        command = ['openssl', 'smime',
                '-verify',
                '-in', manifest,
                '-content', signature,
                '-inform', 'der',
                '-noverify']

        self._cmd(command)

    def save(self, dest):
        with zipfile.ZipFile(dest, 'w', compression=zipfile.ZIP_DEFLATED) as zipped:
            for uncompressed_file in self.files:
                zipped.write(uncompressed_file, os.path.basename(uncompressed_file))

            zipped.write(self.manifest_file, 'manifest.json')
            zipped.write(self.signature_file, 'signature')
            zipped.write(self.pass_file, 'pass.json')

    def cleanup(self):
        os.unlink(self.manifest_file)
        os.unlink(self.signature_file)
        os.unlink(self.pass_file)
