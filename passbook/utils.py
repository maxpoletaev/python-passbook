from subprocess import call


def extract_cert_file(pkcs12, cert_name='cert.pem'):
    ret = call(['openssl', 'pkcs12', '-in', pkcs12, '-clcerts', '-nokeys', '-out', cert_name])
    assert ret == 0, 'Failed to generate pkcs12 certificate'


def extract_key_file(pkcs12, key_name='key.pem'):
    ret = call(['openssl', 'pkcs12', '-in', pkcs12, '-nocerts', '-out', key_name])
    assert ret == 0, 'Failed to generate pkcs12 key file'
