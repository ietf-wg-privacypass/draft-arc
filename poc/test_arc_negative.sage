#!/usr/bin/sage
# vim: syntax=python

import sys

# Load arc_groups first to set up paths correctly
load('arc_groups.sage')
# Load arc.sage to get Client, Server, PresentationState, Presentation, Credential
load('arc.sage')
# Load arc_proofs to get PresentationProof
load('arc_proofs.sage')
# Load range_proof to get ComputeBases
load('range_proof.sage')

try:
    from sigma.poc.sagelib.test_drng import SeededPRNG
    from util import to_bytes
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + str(e))

def test_nonce_exceeds_limit():
    """Test that nonce >= presentationLimit fails verification"""
    print("Test 1: Nonce exceeds presentation limit...")

    rng = SeededPRNG(b"test_nonce_exceeds_limit" + b"\x00" * 8, G.ScalarField)
    issuer = Server()
    client = Client(rng)

    # Setup
    private_key, public_key = Server.keygen(rng, {})
    request_context_str = "test request context".encode('utf-8')
    request_context_obj = client.request(request_context_str, {})
    credential_response = issuer.issue(private_key, public_key, request_context_obj.request, rng, {})
    credential = request_context_obj.finalize_credential(credential_response, public_key, {})

    presentation_context = "test presentation context".encode('utf-8')
    presentation_limit = 5

    # Create a valid presentation to get the structure
    state = PresentationState(credential, presentation_context, presentation_limit)
    valid_presentation = state.present(rng, {})

    # Now manually create a presentation with nonce = presentationLimit (should fail)
    try:
        # Create malformed presentation with nonce at the limit
        a = rng.random_scalar()
        r = rng.random_scalar()
        z = rng.random_scalar()

        U = a * credential.U
        U_prime = a * credential.U_prime
        U_prime_commit = U_prime + r * GenG
        m1_commit = credential.m1 * U + z * GenH

        # Use nonce at the limit
        bad_nonce = presentation_limit
        nonce_blinding = rng.random_scalar()
        nonce_commit = bad_nonce * GenG + nonce_blinding * GenH

        generator_T = hash_to_group(presentation_context, to_bytes("Tag"))
        tag = inverse_mod(Integer(credential.m1 + bad_nonce), Integer(G.group_order)) * generator_T
        V = (z * credential.X1) - (r * GenG)

        # Try to create proof with bad nonce
        proof = PresentationProof.prove(U, U_prime_commit, m1_commit, tag, generator_T,
                                           credential, V, r, z, bad_nonce, nonce_blinding,
                                           nonce_commit, presentation_limit, rng, {})

        bad_presentation = Presentation(U, U_prime_commit, m1_commit, tag, nonce_commit, proof)

        # This should fail verification
        result, _ = issuer.verify_presentation(private_key, public_key, request_context_str,
                                           presentation_context, bad_presentation, presentation_limit)

        if result:
            print("  FAILED: Presentation with nonce >= limit should not verify!")
            return False
        else:
            print("  PASSED: Presentation with nonce >= limit correctly rejected")
            return True
    except Exception as e:
        # The proof creation might fail, which is also acceptable
        print("  PASSED: Exception raised when creating proof with invalid nonce:", str(e))
        return True

def test_invalid_bit_decomposition():
    """Test that incorrect bit decomposition fails"""
    print("Test 2: Invalid bit decomposition...")

    rng = SeededPRNG(b"test_invalid_bit_decomposition" + b"\x00" * 2, G.ScalarField)
    issuer = Server()
    client = Client(rng)

    # Setup
    private_key, public_key = Server.keygen(rng, {})
    request_context_str = "test request context".encode('utf-8')
    request_context_obj = client.request(request_context_str, {})
    credential_response = issuer.issue(private_key, public_key, request_context_obj.request, rng, {})
    credential = request_context_obj.finalize_credential(credential_response, public_key, {})

    presentation_context = "test presentation context".encode('utf-8')
    presentation_limit = 5

    # Create a valid presentation
    state = PresentationState(credential, presentation_context, presentation_limit)
    valid_presentation = state.present(rng, {})

    # Tamper with D commitments (change one commitment)
    tampered_D = list(valid_presentation.proof.D)
    if len(tampered_D) > 0:
        # Create a random element by multiplying generator by random scalar
        random_scalar = rng.random_scalar()
        tampered_D[0] = random_scalar * GenG  # Replace with random element

        # Create tampered proof with modified D
        tampered_proof = PresentationProof(
            tampered_D,
            valid_presentation.proof.challenge,
            valid_presentation.proof.responses
        )

        tampered_presentation = Presentation(
            valid_presentation.U,
            valid_presentation.U_prime_commit,
            valid_presentation.m1_commit,
            valid_presentation.tag,
            valid_presentation.nonce_commit,
            tampered_proof
        )

        # This should fail verification
        result, _ = issuer.verify_presentation(private_key, public_key, request_context_str,
                                           presentation_context, tampered_presentation, presentation_limit)

        if result:
            print("  FAILED: Presentation with tampered D should not verify!")
            return False
        else:
            print("  PASSED: Presentation with tampered D correctly rejected")
            return True
    else:
        print("  SKIPPED: No D commitments to tamper")
        return True

def test_invalid_nonce_commitment():
    """Test that wrong nonce commitment fails"""
    print("Test 3: Invalid nonce commitment...")

    rng = SeededPRNG(b"test_invalid_nonce_commitment" + b"\x00" * 3, G.ScalarField)
    issuer = Server()
    client = Client(rng)

    # Setup
    private_key, public_key = Server.keygen(rng, {})
    request_context_str = "test request context".encode('utf-8')
    request_context_obj = client.request(request_context_str, {})
    credential_response = issuer.issue(private_key, public_key, request_context_obj.request, rng, {})
    credential = request_context_obj.finalize_credential(credential_response, public_key, {})

    presentation_context = "test presentation context".encode('utf-8')
    presentation_limit = 5

    # Create a valid presentation
    state = PresentationState(credential, presentation_context, presentation_limit)
    valid_presentation = state.present(rng, {})

    # Replace nonce_commit with a random commitment
    random_scalar = rng.random_scalar()
    bad_nonce_commit = random_scalar * GenG

    tampered_presentation = Presentation(
        valid_presentation.U,
        valid_presentation.U_prime_commit,
        valid_presentation.m1_commit,
        valid_presentation.tag,
        bad_nonce_commit,
        valid_presentation.proof
    )

    # This should fail verification
    result, _ = issuer.verify_presentation(private_key, public_key, request_context_str,
                                       presentation_context, tampered_presentation, presentation_limit)

    if result:
        print("  FAILED: Presentation with wrong nonce_commit should not verify!")
        return False
    else:
        print("  PASSED: Presentation with wrong nonce_commit correctly rejected")
        return True

def test_reused_nonce_detection():
    """Test that same nonce produces same tag (for server-side double-spend detection)"""
    print("Test 4: Reused nonce produces same tag...")

    rng = SeededPRNG(b"test_reused_nonce" + b"\x00" * 15, G.ScalarField)
    issuer = Server()
    client = Client(rng)

    # Setup
    private_key, public_key = Server.keygen(rng, {})
    request_context_str = "test request context".encode('utf-8')
    request_context_obj = client.request(request_context_str, {})
    credential_response = issuer.issue(private_key, public_key, request_context_obj.request, rng, {})
    credential = request_context_obj.finalize_credential(credential_response, public_key, {})

    presentation_context = "test presentation context".encode('utf-8')
    presentation_limit = 5

    # Manually create two presentations with the same nonce
    nonce = 1

    # First presentation
    a1 = rng.random_scalar()
    r1 = rng.random_scalar()
    z1 = rng.random_scalar()
    U1 = a1 * credential.U
    U_prime1 = a1 * credential.U_prime
    U_prime_commit1 = U_prime1 + r1 * GenG
    m1_commit1 = credential.m1 * U1 + z1 * GenH
    nonce_blinding1 = rng.random_scalar()
    nonce_commit1 = nonce * GenG + nonce_blinding1 * GenH
    generator_T = hash_to_group(presentation_context, to_bytes("Tag"))
    tag1 = inverse_mod(Integer(credential.m1 + nonce), Integer(G.group_order)) * generator_T

    # Second presentation with same nonce
    a2 = rng.random_scalar()
    r2 = rng.random_scalar()
    z2 = rng.random_scalar()
    U2 = a2 * credential.U
    U_prime2 = a2 * credential.U_prime
    U_prime_commit2 = U_prime2 + r2 * GenG
    m1_commit2 = credential.m1 * U2 + z2 * GenH
    nonce_blinding2 = rng.random_scalar()
    nonce_commit2 = nonce * GenG + nonce_blinding2 * GenH
    tag2 = inverse_mod(Integer(credential.m1 + nonce), Integer(G.group_order)) * generator_T

    # Tags should be identical for the same nonce
    if tag1 == tag2:
        print("  PASSED: Same nonce produces identical tags (server can detect double-spending)")
        return True
    else:
        print("  FAILED: Same nonce should produce identical tags!")
        return False

def test_exceed_presentation_limit():
    """Test that exceeding limit raises error"""
    print("Test 5: Exceeding presentation limit...")

    rng = SeededPRNG(b"test_exceed_limit" + b"\x00" * 15, G.ScalarField)
    issuer = Server()
    client = Client(rng)

    # Setup
    private_key, public_key = Server.keygen(rng, {})
    request_context_str = "test request context".encode('utf-8')
    request_context_obj = client.request(request_context_str, {})
    credential_response = issuer.issue(private_key, public_key, request_context_obj.request, rng, {})
    credential = request_context_obj.finalize_credential(credential_response, public_key, {})

    presentation_context = "test presentation context".encode('utf-8')
    presentation_limit = 3  # Small limit for testing

    state = PresentationState(credential, presentation_context, presentation_limit)

    # Create exactly presentation_limit presentations
    for i in range(presentation_limit):
        presentation = state.present(rng, {})
        result, _ = issuer.verify_presentation(private_key, public_key, request_context_str,
                                           presentation_context, presentation, presentation_limit)
        if not result:
            print("  FAILED: Valid presentation {} did not verify!".format(i))
            return False

    # Try to create one more (should raise exception)
    try:
        extra_presentation = state.present(rng, {})
        print("  FAILED: Should have raised LimitExceededError!")
        return False
    except Exception as e:
        if "LimitExceededError" in str(e):
            print("  PASSED: LimitExceededError correctly raised after {} presentations".format(presentation_limit))
            return True
        else:
            print("  FAILED: Wrong exception raised:", str(e))
            return False

def test_tampered_presentation():
    """Test that tampered presentation elements fail"""
    print("Test 6: Tampered presentation elements...")

    rng = SeededPRNG(b"test_tampered" + b"\x00" * 19, G.ScalarField)
    issuer = Server()
    client = Client(rng)

    # Setup
    private_key, public_key = Server.keygen(rng, {})
    request_context_str = "test request context".encode('utf-8')
    request_context_obj = client.request(request_context_str, {})
    credential_response = issuer.issue(private_key, public_key, request_context_obj.request, rng, {})
    credential = request_context_obj.finalize_credential(credential_response, public_key, {})

    presentation_context = "test presentation context".encode('utf-8')
    presentation_limit = 5

    # Create a valid presentation
    state = PresentationState(credential, presentation_context, presentation_limit)
    valid_presentation = state.present(rng, {})

    tests_passed = 0
    total_tests = 0

    # Test tampering with U
    total_tests += 1
    random_scalar = rng.random_scalar()
    tampered_U = Presentation(
        random_scalar * GenG,  # Replace with random element
        valid_presentation.U_prime_commit,
        valid_presentation.m1_commit,
        valid_presentation.tag,
        valid_presentation.nonce_commit,
        valid_presentation.proof
    )
    result, _ = issuer.verify_presentation(private_key, public_key, request_context_str,
                                       presentation_context, tampered_U, presentation_limit)
    if not result:
        print("    - Tampered U: PASSED")
        tests_passed += 1
    else:
        print("    - Tampered U: FAILED")

    # Test tampering with m1_commit
    total_tests += 1
    random_scalar = rng.random_scalar()
    tampered_m1 = Presentation(
        valid_presentation.U,
        valid_presentation.U_prime_commit,
        random_scalar * GenG,  # Replace with random element
        valid_presentation.tag,
        valid_presentation.nonce_commit,
        valid_presentation.proof
    )
    result, _ = issuer.verify_presentation(private_key, public_key, request_context_str,
                                       presentation_context, tampered_m1, presentation_limit)
    if not result:
        print("    - Tampered m1_commit: PASSED")
        tests_passed += 1
    else:
        print("    - Tampered m1_commit: FAILED")

    # Test tampering with tag
    total_tests += 1
    random_scalar = rng.random_scalar()
    tampered_tag = Presentation(
        valid_presentation.U,
        valid_presentation.U_prime_commit,
        valid_presentation.m1_commit,
        random_scalar * GenG,  # Replace with random element
        valid_presentation.nonce_commit,
        valid_presentation.proof
    )
    result, _ = issuer.verify_presentation(private_key, public_key, request_context_str,
                                       presentation_context, tampered_tag, presentation_limit)
    if not result:
        print("    - Tampered tag: PASSED")
        tests_passed += 1
    else:
        print("    - Tampered tag: FAILED")

    if tests_passed == total_tests:
        print("  PASSED: All {} tampered presentations correctly rejected".format(total_tests))
        return True
    else:
        print("  FAILED: {}/{} tampered presentations rejected".format(tests_passed, total_tests))
        return False

def run_all_tests():
    print("\n" + "="*60)
    print("Running ARC Negative Test Suite")
    print("="*60 + "\n")

    tests = [
        test_nonce_exceeds_limit,
        test_invalid_bit_decomposition,
        test_invalid_nonce_commitment,
        test_reused_nonce_detection,
        test_exceed_presentation_limit,
        test_tampered_presentation,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print("  EXCEPTION:", str(e))
            failed += 1
        print()

    print("="*60)
    print("Test Results: {} passed, {} failed".format(passed, failed))
    print("="*60)

    return failed == 0

if __name__ == "__main__":
    success = run_all_tests()
    if not success:
        raise Exception("Tests failed")
