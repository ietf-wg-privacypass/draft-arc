#!/usr/bin/sage
# vim: syntax=python

import sys
import json

# Load arc_groups first to set up paths correctly
load('arc_groups.sage')
# Load arc.sage to get Client, Server, PresentationState
load('arc.sage')

try:
    from sigma.poc.sagelib.test_drng import SeededPRNG
    from util import to_hex
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + str(e))

def wrap_write(fh, arg, *args):
    line_length = 68
    string = " ".join( [arg] + list(args))
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            fh.write(hunk + "\n")

def write_blob(fh, name, blob):
    wrap_write(fh, name + ' = ' + to_hex(blob))

def write_value(fh, name, value):
    wrap_write(fh, name + ' = ' + value)

def write_group_vectors(fh, label, vector):
    fh.write("// " + label + "\n")
    for key in vector:
        write_value(fh, key, vector[key])

def main(path="vectors"):
    # Pad seed to 32 bytes (SeededPRNG requirement)
    seed = b"test vector seed" + b'\x00' * 16
    rng = SeededPRNG(seed, G.ScalarField)
    issuer = Server()
    client = Client(rng)

    key_vectors = {}
    request_vectors = {}
    response_vectors = {}
    credential_vectors = {}
    presentation_vectors_1 = {}
    presentation_vectors_2 = {}

    private_key, public_key = Server.keygen(rng, key_vectors)

    sample_request_context = "test request context".encode('utf-8')
    request_context = client.request(sample_request_context, request_vectors)
    credential_response = issuer.issue(private_key, public_key, request_context.request, rng, response_vectors)
    credential = request_context.finalize_credential(credential_response, public_key, credential_vectors)

    assert credential != None

    sample_presentation_context = "test presentation context".encode('utf-8')
    presentation_limit = 2
    presentation_state = PresentationState(credential, sample_presentation_context, presentation_limit)

    presentation_1 = presentation_state.present(rng, presentation_vectors_1)
    validity_1, tag_1 = issuer.verify_presentation(private_key, public_key, sample_request_context, sample_presentation_context, presentation_1, presentation_limit)
    assert validity_1

    presentation_2 = presentation_state.present(rng, presentation_vectors_2)
    validity_2, tag_2 = issuer.verify_presentation(private_key, public_key, sample_request_context, sample_presentation_context, presentation_2, presentation_limit)
    assert validity_2

    vectors = {}
    vectors[context_string.decode('utf-8')] = {
        "ServerKey": key_vectors,
        "CredentialRequest": request_vectors,
        "CredentialResponse": response_vectors,
        "Credential": credential_vectors,
        "Presentation1": presentation_vectors_1,
        "Presentation2": presentation_vectors_2,
    }

    with open(path + "/allVectors.json", 'wt') as f:
        json.dump(vectors, f, sort_keys=True, indent=2)

    with open(path + "/allVectors.txt", 'wt') as f:
        for suite in vectors:
            f.write("## " + suite + "\n")
            f.write("\n")
            f.write("~~~\n")
            for group in vectors[suite]:
                write_group_vectors(f, group, vectors[suite][group])
                f.write("\n")
            f.write("~~~\n")

if __name__ == "__main__":
    main()
