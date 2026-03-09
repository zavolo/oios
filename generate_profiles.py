import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'build-system/Make'))
from GenerateProfiles import generate_provisioning_profiles

generate_provisioning_profiles(
    source_path='build-system/fake-codesigning/profiles',
    destination_path='build-system/fake-codesigning/profiles',
    certs_path='build-system/fake-codesigning/certs'
)
