#!/usr/bin/sage
# vim: syntax=python

import sys

try:
    from sagelib.test_drng import TestDRNG
    from sagelib.arc_groups import G, GenG, GenH, context_string
    from sagelib.range_proof import MakeRangeProofHelper, VerifyRangeProofHelper, ComputeBases
    from sagelib.zkp import Prover, Verifier
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + str(e))

def test_valid_nonce_in_range():
    """Test that valid nonces in [0, presentationLimit) verify correctly"""
    print("Test 1: Valid nonces in range...")

    rng = TestDRNG("test_valid_nonce".encode('utf-8'))
    presentation_limit = 10

    # Test several valid nonces
    test_nonces = [0, 1, 5, 9]  # All in [0, 10)

    for nonce in test_nonces:
        # Create prover
        prover = Prover(context_string + "RangeProofTest", rng, {})

        # Generate blinding factor and commitment
        nonce_blinding = G.random_scalar(rng)
        nonce_commit = nonce * GenG + nonce_blinding * GenH

        # Append variables to prover
        nonce_var = prover.append_scalar("nonce", nonce)
        nonce_blinding_var = prover.append_scalar("nonceBlinding", nonce_blinding)
        gen_G_var = prover.append_element("genG", GenG)
        gen_H_var = prover.append_element("genH", GenH)
        nonce_commit_var = prover.append_element("nonceCommit", nonce_commit)

        # Add constraint for nonce commitment
        prover.constrain(nonce_commit_var, [(nonce_var, gen_G_var), (nonce_blinding_var, gen_H_var)])

        # Add range proof constraints
        (prover, D) = MakeRangeProofHelper(prover, nonce, nonce_blinding, presentation_limit, gen_G_var, gen_H_var)

        # Generate proof
        proof = prover.prove()

        # Create verifier
        verifier = Verifier(context_string + "RangeProofTest")

        # Append variables to verifier (no witness values)
        nonce_var = verifier.append_scalar("nonce")
        nonce_blinding_var = verifier.append_scalar("nonceBlinding")
        gen_G_var = verifier.append_element("genG", GenG)
        gen_H_var = verifier.append_element("genH", GenH)
        nonce_commit_var = verifier.append_element("nonceCommit", nonce_commit)

        # Add constraint for nonce commitment
        verifier.constrain(nonce_commit_var, [(nonce_var, gen_G_var), (nonce_blinding_var, gen_H_var)])

        # Verify range proof
        (verifier, sum_valid) = VerifyRangeProofHelper(verifier, D, nonce_commit, presentation_limit, gen_G_var, gen_H_var)

        if not sum_valid:
            print("  FAILED: Sum check failed for nonce = {}".format(nonce))
            return False

        # Verify the proof
        if not verifier.verify(proof):
            print("  FAILED: Proof verification failed for nonce = {}".format(nonce))
            return False

    print("  PASSED: All valid nonces verified correctly")
    return True

def test_nonce_equals_limit():
    """Test that nonce == presentationLimit fails verification"""
    print("Test 2: Nonce equals presentation limit...")

    rng = TestDRNG("test_nonce_equals_limit".encode('utf-8'))
    presentation_limit = 5
    nonce = 5  # Equal to limit, should fail

    try:
        # Create prover
        prover = Prover(context_string + "RangeProofTest", rng, {})

        # Generate blinding factor and commitment
        nonce_blinding = G.random_scalar(rng)
        nonce_commit = nonce * GenG + nonce_blinding * GenH

        # Append variables to prover
        nonce_var = prover.append_scalar("nonce", nonce)
        nonce_blinding_var = prover.append_scalar("nonceBlinding", nonce_blinding)
        gen_G_var = prover.append_element("genG", GenG)
        gen_H_var = prover.append_element("genH", GenH)
        nonce_commit_var = prover.append_element("nonceCommit", nonce_commit)

        # Add constraint for nonce commitment
        prover.constrain(nonce_commit_var, [(nonce_var, gen_G_var), (nonce_blinding_var, gen_H_var)])

        # Add range proof constraints - this should create an invalid decomposition
        (prover, D) = MakeRangeProofHelper(prover, nonce, nonce_blinding, presentation_limit, gen_G_var, gen_H_var)

        # Generate proof
        proof = prover.prove()

        # Create verifier
        verifier = Verifier(context_string + "RangeProofTest")

        # Append variables to verifier
        nonce_var = verifier.append_scalar("nonce")
        nonce_blinding_var = verifier.append_scalar("nonceBlinding")
        gen_G_var = verifier.append_element("genG", GenG)
        gen_H_var = verifier.append_element("genH", GenH)
        nonce_commit_var = verifier.append_element("nonceCommit", nonce_commit)

        # Add constraint for nonce commitment
        verifier.constrain(nonce_commit_var, [(nonce_var, gen_G_var), (nonce_blinding_var, gen_H_var)])

        # Verify range proof
        (verifier, sum_valid) = VerifyRangeProofHelper(verifier, D, nonce_commit, presentation_limit, gen_G_var, gen_H_var)

        # Either sum should be invalid, or proof should fail
        if not sum_valid:
            print("  PASSED: Sum check correctly failed for nonce == limit")
            return True

        if not verifier.verify(proof):
            print("  PASSED: Proof verification correctly failed for nonce == limit")
            return True

        print("  FAILED: Nonce == limit should not verify!")
        return False

    except Exception as e:
        print("  PASSED: Exception raised for nonce == limit:", str(e))
        return True

def test_nonce_exceeds_limit():
    """Test that nonce > presentationLimit fails verification"""
    print("Test 3: Nonce exceeds presentation limit...")

    rng = TestDRNG("test_nonce_exceeds_limit".encode('utf-8'))
    presentation_limit = 5
    nonce = 10  # Exceeds limit, should fail

    try:
        # Create prover
        prover = Prover(context_string + "RangeProofTest", rng, {})

        # Generate blinding factor and commitment
        nonce_blinding = G.random_scalar(rng)
        nonce_commit = nonce * GenG + nonce_blinding * GenH

        # Append variables to prover
        nonce_var = prover.append_scalar("nonce", nonce)
        nonce_blinding_var = prover.append_scalar("nonceBlinding", nonce_blinding)
        gen_G_var = prover.append_element("genG", GenG)
        gen_H_var = prover.append_element("genH", GenH)
        nonce_commit_var = prover.append_element("nonceCommit", nonce_commit)

        # Add constraint for nonce commitment
        prover.constrain(nonce_commit_var, [(nonce_var, gen_G_var), (nonce_blinding_var, gen_H_var)])

        # Add range proof constraints - this should create an invalid decomposition
        (prover, D) = MakeRangeProofHelper(prover, nonce, nonce_blinding, presentation_limit, gen_G_var, gen_H_var)

        # Generate proof
        proof = prover.prove()

        # Create verifier
        verifier = Verifier(context_string + "RangeProofTest")

        # Append variables to verifier
        nonce_var = verifier.append_scalar("nonce")
        nonce_blinding_var = verifier.append_scalar("nonceBlinding")
        gen_G_var = verifier.append_element("genG", GenG)
        gen_H_var = verifier.append_element("genH", GenH)
        nonce_commit_var = verifier.append_element("nonceCommit", nonce_commit)

        # Add constraint for nonce commitment
        verifier.constrain(nonce_commit_var, [(nonce_var, gen_G_var), (nonce_blinding_var, gen_H_var)])

        # Verify range proof
        (verifier, sum_valid) = VerifyRangeProofHelper(verifier, D, nonce_commit, presentation_limit, gen_G_var, gen_H_var)

        # Either sum should be invalid, or proof should fail
        if not sum_valid:
            print("  PASSED: Sum check correctly failed for nonce > limit")
            return True

        if not verifier.verify(proof):
            print("  PASSED: Proof verification correctly failed for nonce > limit")
            return True

        print("  FAILED: Nonce > limit should not verify!")
        return False

    except Exception as e:
        print("  PASSED: Exception raised for nonce > limit:", str(e))
        return True

def test_negative_nonce():
    """Test that negative nonce fails verification"""
    print("Test 4: Negative nonce...")

    rng = TestDRNG("test_negative_nonce".encode('utf-8'))
    presentation_limit = 5

    # In SageMath, we need to handle negative values carefully
    # A negative nonce would wrap around modulo the group order
    # We'll create a nonce that's negative in the integer sense
    nonce = -1

    try:
        # Create prover
        prover = Prover(context_string + "RangeProofTest", rng, {})

        # Generate blinding factor and commitment
        nonce_blinding = G.random_scalar(rng)
        # This will compute (-1) * GenG + nonce_blinding * GenH
        # which is equivalent to (order - 1) * GenG + nonce_blinding * GenH
        nonce_commit = nonce * GenG + nonce_blinding * GenH

        # Append variables to prover
        nonce_var = prover.append_scalar("nonce", nonce)
        nonce_blinding_var = prover.append_scalar("nonceBlinding", nonce_blinding)
        gen_G_var = prover.append_element("genG", GenG)
        gen_H_var = prover.append_element("genH", GenH)
        nonce_commit_var = prover.append_element("nonceCommit", nonce_commit)

        # Add constraint for nonce commitment
        prover.constrain(nonce_commit_var, [(nonce_var, gen_G_var), (nonce_blinding_var, gen_H_var)])

        # Add range proof constraints - this should fail or create invalid decomposition
        (prover, D) = MakeRangeProofHelper(prover, nonce, nonce_blinding, presentation_limit, gen_G_var, gen_H_var)

        # Generate proof
        proof = prover.prove()

        # Create verifier
        verifier = Verifier(context_string + "RangeProofTest")

        # Append variables to verifier
        nonce_var = verifier.append_scalar("nonce")
        nonce_blinding_var = verifier.append_scalar("nonceBlinding")
        gen_G_var = verifier.append_element("genG", GenG)
        gen_H_var = verifier.append_element("genH", GenH)
        nonce_commit_var = verifier.append_element("nonceCommit", nonce_commit)

        # Add constraint for nonce commitment
        verifier.constrain(nonce_commit_var, [(nonce_var, gen_G_var), (nonce_blinding_var, gen_H_var)])

        # Verify range proof
        (verifier, sum_valid) = VerifyRangeProofHelper(verifier, D, nonce_commit, presentation_limit, gen_G_var, gen_H_var)

        # Either sum should be invalid, or proof should fail
        if not sum_valid:
            print("  PASSED: Sum check correctly failed for negative nonce")
            return True

        if not verifier.verify(proof):
            print("  PASSED: Proof verification correctly failed for negative nonce")
            return True

        print("  FAILED: Negative nonce should not verify!")
        return False

    except Exception as e:
        print("  PASSED: Exception raised for negative nonce:", str(e))
        return True

def test_tampered_bit_commitments():
    """Test that tampered D commitments fail verification"""
    print("Test 5: Tampered bit commitments...")

    rng = TestDRNG("test_tampered_D".encode('utf-8'))
    presentation_limit = 10
    nonce = 5  # Valid nonce

    # Create prover
    prover = Prover(context_string + "RangeProofTest", rng, {})

    # Generate blinding factor and commitment
    nonce_blinding = G.random_scalar(rng)
    nonce_commit = nonce * GenG + nonce_blinding * GenH

    # Append variables to prover
    nonce_var = prover.append_scalar("nonce", nonce)
    nonce_blinding_var = prover.append_scalar("nonceBlinding", nonce_blinding)
    gen_G_var = prover.append_element("genG", GenG)
    gen_H_var = prover.append_element("genH", GenH)
    nonce_commit_var = prover.append_element("nonceCommit", nonce_commit)

    # Add constraint for nonce commitment
    prover.constrain(nonce_commit_var, [(nonce_var, gen_G_var), (nonce_blinding_var, gen_H_var)])

    # Add range proof constraints
    (prover, D) = MakeRangeProofHelper(prover, nonce, nonce_blinding, presentation_limit, gen_G_var, gen_H_var)

    # Generate proof
    proof = prover.prove()

    # Tamper with D commitments
    if len(D) > 0:
        tampered_D = list(D)
        random_scalar = G.random_scalar(rng)
        tampered_D[0] = random_scalar * GenG  # Replace first commitment with random value

        # Create verifier
        verifier = Verifier(context_string + "RangeProofTest")

        # Append variables to verifier
        nonce_var = verifier.append_scalar("nonce")
        nonce_blinding_var = verifier.append_scalar("nonceBlinding")
        gen_G_var = verifier.append_element("genG", GenG)
        gen_H_var = verifier.append_element("genH", GenH)
        nonce_commit_var = verifier.append_element("nonceCommit", nonce_commit)

        # Add constraint for nonce commitment
        verifier.constrain(nonce_commit_var, [(nonce_var, gen_G_var), (nonce_blinding_var, gen_H_var)])

        # Verify range proof with tampered D
        (verifier, sum_valid) = VerifyRangeProofHelper(verifier, tampered_D, nonce_commit, presentation_limit, gen_G_var, gen_H_var)

        # Either sum should be invalid, or proof should fail
        if not sum_valid:
            print("  PASSED: Sum check correctly failed for tampered D")
            return True

        if not verifier.verify(proof):
            print("  PASSED: Proof verification correctly failed for tampered D")
            return True

        print("  FAILED: Tampered D commitments should not verify!")
        return False
    else:
        print("  SKIPPED: No D commitments to tamper")
        return True

def test_wrong_sum():
    """Test that D commitments that sum to wrong value fail verification"""
    print("Test 6: D commitments sum to wrong value...")

    rng = TestDRNG("test_wrong_sum".encode('utf-8'))
    presentation_limit = 10
    nonce = 5  # Valid nonce

    # Create prover for nonce 5
    prover = Prover(context_string + "RangeProofTest", rng, {})

    # Generate blinding factor and commitment
    nonce_blinding = G.random_scalar(rng)
    nonce_commit = nonce * GenG + nonce_blinding * GenH

    # Append variables to prover
    nonce_var = prover.append_scalar("nonce", nonce)
    nonce_blinding_var = prover.append_scalar("nonceBlinding", nonce_blinding)
    gen_G_var = prover.append_element("genG", GenG)
    gen_H_var = prover.append_element("genH", GenH)
    nonce_commit_var = prover.append_element("nonceCommit", nonce_commit)

    # Add constraint for nonce commitment
    prover.constrain(nonce_commit_var, [(nonce_var, gen_G_var), (nonce_blinding_var, gen_H_var)])

    # Add range proof constraints
    (prover, D) = MakeRangeProofHelper(prover, nonce, nonce_blinding, presentation_limit, gen_G_var, gen_H_var)

    # Generate proof
    proof = prover.prove()

    # Create a different nonce commitment (for nonce 7 instead of 5)
    different_nonce = 7
    different_nonce_blinding = G.random_scalar(rng)
    wrong_nonce_commit = different_nonce * GenG + different_nonce_blinding * GenH

    # Create verifier
    verifier = Verifier(context_string + "RangeProofTest")

    # Append variables to verifier
    nonce_var = verifier.append_scalar("nonce")
    nonce_blinding_var = verifier.append_scalar("nonceBlinding")
    gen_G_var = verifier.append_element("genG", GenG)
    gen_H_var = verifier.append_element("genH", GenH)
    nonce_commit_var = verifier.append_element("nonceCommit", wrong_nonce_commit)  # Wrong commitment

    # Add constraint for nonce commitment
    verifier.constrain(nonce_commit_var, [(nonce_var, gen_G_var), (nonce_blinding_var, gen_H_var)])

    # Verify range proof - D should not sum to wrong_nonce_commit
    (verifier, sum_valid) = VerifyRangeProofHelper(verifier, D, wrong_nonce_commit, presentation_limit, gen_G_var, gen_H_var)

    if not sum_valid:
        print("  PASSED: Sum check correctly failed for wrong nonce commitment")
        return True

    # Even if sum_valid passes (shouldn't), the proof should fail
    if not verifier.verify(proof):
        print("  PASSED: Proof verification correctly failed for wrong nonce commitment")
        return True

    print("  FAILED: Wrong nonce commitment should not verify!")
    return False

def test_bases_computation():
    """Test that ComputeBases works correctly for various limits"""
    print("Test 7: ComputeBases correctness...")

    test_cases = [
        (2, [1]),           # 2 = 2^1, bases = [1]
        (3, [2, 1]),        # 3 = 2 + 1, bases = [2, 1]
        (4, [2, 1]),        # 4 = 2 + 2, but last base is 4-1-2 = 1, bases = [2, 1]
        (5, [2, 2]),        # 5 = 2 + 3, but last base is 5-1-2 = 2, bases = [2, 2]
        (8, [4, 2, 1]),     # 8 = 4 + 2 + 2, but last base is 8-1-2-4 = 1, bases = [4, 2, 1]
        (10, [4, 2, 3]),    # 10 = 4 + 2 + 4, but last base is 10-1-2-4 = 3, bases = [4, 2, 3]
    ]

    all_passed = True
    for limit, expected in test_cases:
        bases = ComputeBases(limit)
        # Check that we can represent all values in [0, limit)
        max_representable = sum(bases) + 1
        if max_representable != limit:
            print("  FAILED: ComputeBases({}) gives max {} instead of {}".format(limit, max_representable, limit))
            print("    bases = {}, expected = {}".format(bases, expected))
            all_passed = False
            continue

        # Check all values can be represented
        can_represent_all = True
        for val in range(limit):
            remainder = val
            for base in bases:
                if remainder >= base:
                    remainder -= base
            if remainder != 0:
                can_represent_all = False
                break

        if not can_represent_all:
            print("  FAILED: ComputeBases({}) cannot represent all values in [0, {})".format(limit, limit))
            print("    bases = {}".format(bases))
            all_passed = False

    if all_passed:
        print("  PASSED: ComputeBases works correctly for all test cases")

    return all_passed

def run_all_tests():
    print("\n" + "="*60)
    print("Running Range Proof Test Suite")
    print("="*60 + "\n")

    tests = [
        test_bases_computation,
        test_valid_nonce_in_range,
        test_nonce_equals_limit,
        test_nonce_exceeds_limit,
        test_negative_nonce,
        test_tampered_bit_commitments,
        test_wrong_sum,
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
            import traceback
            traceback.print_exc()
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
