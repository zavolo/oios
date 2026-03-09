import sys
import os
import subprocess
import base64
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'build-system/Make'))
from BuildEnvironment import run_executable_with_output


def get_signing_identity_from_p12(p12_path, p12_password=''):
    for legacy in [[], ['-legacy']]:
        proc = subprocess.Popen(
            ['openssl', 'pkcs12', '-in', p12_path, '-passin', 'pass:' + p12_password, '-nokeys'] + legacy,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        cert_pem, _ = proc.communicate()
        if not cert_pem:
            continue
        proc2 = subprocess.Popen(
            ['openssl', 'x509', '-noout', '-subject', '-nameopt', 'oneline,-esc_msb'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        subject, _ = proc2.communicate(cert_pem)
        subject = subject.decode('utf-8').strip()
        if 'CN = ' in subject:
            return cert_pem, subject.split('CN = ')[-1].split(',')[0].strip()
        if 'CN=' in subject:
            return cert_pem, subject.split('CN=')[-1].split(',')[0].strip()
    return None, None


def get_certificate_base64(cert_pem):
    proc = subprocess.Popen(
        ['openssl', 'x509', '-outform', 'DER'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    cert_der, _ = proc.communicate(cert_pem)
    return base64.b64encode(cert_der).decode('utf-8')


def setup_temp_keychain(p12_path, p12_password=''):
    keychain_name = 'generate-profiles-temp.keychain'
    keychain_password = 'temp123'
    run_executable_with_output('security', arguments=['delete-keychain', keychain_name], check_result=False)
    run_executable_with_output('security', arguments=['create-keychain', '-p', keychain_password, keychain_name], check_result=True)
    existing = run_executable_with_output('security', arguments=['list-keychains', '-d', 'user'])
    run_executable_with_output('security', arguments=['list-keychains', '-d', 'user', '-s', keychain_name, existing.replace('"', '')], check_result=True)
    run_executable_with_output('security', arguments=['set-keychain-settings', keychain_name])
    run_executable_with_output('security', arguments=['unlock-keychain', '-p', keychain_password, keychain_name])
    run_executable_with_output('security', arguments=['import', p12_path, '-k', keychain_name, '-P', p12_password, '-T', '/usr/bin/codesign', '-T', '/usr/bin/security'], check_result=True)
    run_executable_with_output('security', arguments=['set-key-partition-list', '-S', 'apple-tool:,apple:', '-k', keychain_password, keychain_name], check_result=True)
    return keychain_name


def process_provisioning_profile(source, destination, certificate_data, signing_identity, keychain_name):
    parsed_plist = run_executable_with_output('security', arguments=['cms', '-D', '-i', source], check_result=True)
    parsed_plist_file = tempfile.mktemp()
    with open(parsed_plist_file, 'w+') as f:
        f.write(parsed_plist)
    while True:
        check = run_executable_with_output('plutil', arguments=['-extract', 'DeveloperCertificates.0', 'raw', parsed_plist_file], check_result=False)
        if check is None or 'Could not' in str(check):
            break
        run_executable_with_output('plutil', arguments=['-remove', 'DeveloperCertificates.0', parsed_plist_file], check_result=False)
    run_executable_with_output('plutil', arguments=['-insert', 'DeveloperCertificates.0', '-data', certificate_data, parsed_plist_file])
    run_executable_with_output('plutil', arguments=['-remove', 'DER-Encoded-Profile', parsed_plist_file])
    run_executable_with_output('security', arguments=['cms', '-S', '-k', keychain_name, '-N', signing_identity, '-i', parsed_plist_file, '-o', destination], check_result=True)
    os.unlink(parsed_plist_file)


p12_path = 'build-system/fake-codesigning/certs/SelfSigned.p12'
profiles_path = 'build-system/fake-codesigning/profiles'

cert_pem, signing_identity = get_signing_identity_from_p12(p12_path)
if not signing_identity:
    print('Could not extract signing identity')
    sys.exit(1)

print('Using signing identity: {}'.format(signing_identity))
certificate_data = get_certificate_base64(cert_pem)
keychain_name = setup_temp_keychain(p12_path)

try:
    for file_name in os.listdir(profiles_path):
        if file_name.endswith('.mobileprovision'):
            print('Processing {}'.format(file_name))
            process_provisioning_profile(
                source=os.path.join(profiles_path, file_name),
                destination=os.path.join(profiles_path, file_name),
                certificate_data=certificate_data,
                signing_identity=signing_identity,
                keychain_name=keychain_name
            )
    print('Done.')
finally:
    run_executable_with_output('security', arguments=['delete-keychain', keychain_name], check_result=False)
