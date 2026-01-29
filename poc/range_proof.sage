from sagelib.arc_groups import G, GenG, GenH
from math import ceil, log2

def ComputeBases(presentation_limit):
    """
    Compute bases to represent elements in [0, presentation_limit).

    Inputs:
    - presentation_limit: Integer, the maximum value of the range (exclusive).

    Outputs:
    - bases: an array of Scalar bases sorted in descending order.
    """
    remainder = presentation_limit
    bases = []

    # Generate all but the last power-of-two base
    num_bits = ceil(log2(presentation_limit))
    for i in range(num_bits - 1):
        base = 2 ** i
        remainder -= base
        bases.append(Integer(base))

    # Add the final non-power-of-two base
    bases.append(Integer(remainder - 1))

    # Sort in descending order
    return sorted(bases, reverse=True)

def MakeRangeProofHelper(prover, nonce, nonce_blinding, presentation_limit, gen_G_var, gen_H_var):
    """
    Add range proof constraints to prover statement.

    Inputs:
    - prover: Prover statement to which constraints will be added
    - nonce: Integer, the nonce value to prove is in range
    - nonce_blinding: Scalar, the blinding factor for the nonce commitment
    - presentation_limit: Integer, the maximum value of the range (exclusive)
    - gen_G_var: Integer, variable index for generator G
    - gen_H_var: Integer, variable index for generator H

    Outputs:
    - prover: Modified prover statement with range proof constraints added
    - D: [Element], array of commitments to the bit decomposition
    """
    # Compute bit decomposition and commitments
    bases = ComputeBases(presentation_limit)

    # Compute bit decomposition of nonce
    b = []
    remainder = nonce
    for base in bases:
        if remainder >= base:
            remainder -= base
            b.append(Integer(1))
        else:
            b.append(Integer(0))

    # Compute commitments to bits
    D = []
    s = []
    s2 = []
    partial_sum = Integer(0)

    for i in range(len(bases) - 1):
        s_i = G.random_scalar(prover.rng)
        s.append(s_i)
        partial_sum += bases[i] * s_i
        s2_i = (Integer(1) - b[i]) * s_i
        s2.append(s2_i)
        D_i = b[i] * GenG + s_i * GenH
        D.append(D_i)

    # Blinding value for the last bit commitment is chosen strategically
    # so that all the bit commitments will sum up to nonce_commit
    idx = len(bases) - 1
    s_last = inverse_mod(Integer(bases[idx]), G.order()) * (nonce_blinding - partial_sum)
    s.append(s_last)
    s2_last = (Integer(1) - b[idx]) * s_last
    s2.append(s2_last)
    D_last = b[idx] * GenG + s_last * GenH
    D.append(D_last)

    # Append scalar variables with witness values
    vars_b = []
    for i in range(len(b)):
        vars_b.append(prover.append_scalar("b" + str(i), b[i]))

    vars_s = []
    for i in range(len(s)):
        vars_s.append(prover.append_scalar("s" + str(i), s[i]))

    vars_s2 = []
    for i in range(len(s2)):
        vars_s2.append(prover.append_scalar("s2" + str(i), s2[i]))

    # Append element variables for bit commitments D
    vars_D = []
    for i in range(len(D)):
        vars_D.append(prover.append_element("D" + str(i), D[i]))

    # Add constraints proving each b[i] is in {0,1}
    for i in range(len(b)):
        # D[i] = b[i] * generatorG + s[i] * generatorH
        prover.constrain(vars_D[i], [(vars_b[i], gen_G_var), (vars_s[i], gen_H_var)])
        # D[i] = b[i] * D[i] + s2[i] * generatorH (proves b[i] is in {0,1})
        prover.constrain(vars_D[i], [(vars_b[i], vars_D[i]), (vars_s2[i], gen_H_var)])

    return (prover, D)

def VerifyRangeProofHelper(verifier, D, nonce_commit, presentation_limit, gen_G_var, gen_H_var):
    """
    Add range proof constraints to verifier statement and verify sum.

    Inputs:
    - verifier: Verifier statement to which constraints will be added
    - D: [Element], array of commitments to the bit decomposition
    - nonce_commit: Element, the Pedersen commitment to the nonce
    - presentation_limit: Integer, the maximum value of the range (exclusive)
    - gen_G_var: Integer, variable index for generator G
    - gen_H_var: Integer, variable index for generator H

    Outputs:
    - verifier: Modified verifier statement with range proof constraints added
    - validity: Boolean, True if sum(bases[i] * D[i]) == nonce_commit, False otherwise
    """
    bases = ComputeBases(presentation_limit)
    num_bits = len(bases)

    # Append scalar variables without witness values
    vars_b = []
    for i in range(num_bits):
        vars_b.append(verifier.append_scalar("b" + str(i)))

    vars_s = []
    for i in range(num_bits):
        vars_s.append(verifier.append_scalar("s" + str(i)))

    vars_s2 = []
    for i in range(num_bits):
        vars_s2.append(verifier.append_scalar("s2" + str(i)))

    # Append element variables for bit commitments D
    vars_D = []
    for i in range(num_bits):
        vars_D.append(verifier.append_element("D" + str(i), D[i]))

    # Add constraints proving each b[i] is in {0,1}
    for i in range(num_bits):
        # D[i] = b[i] * generatorG + s[i] * generatorH
        verifier.constrain(vars_D[i], [(vars_b[i], gen_G_var), (vars_s[i], gen_H_var)])
        # D[i] = b[i] * D[i] + s2[i] * generatorH
        verifier.constrain(vars_D[i], [(vars_b[i], vars_D[i]), (vars_s2[i], gen_H_var)])

    # Verify the sum check: nonce_commit == sum(bases[i] * D[i])
    # This is done explicitly by computing the sum homomorphically
    sum_D = G.identity()
    for i in range(len(bases)):
        sum_D = sum_D + Integer(bases[i]) * D[i]

    sum_valid = (sum_D == nonce_commit)
    return (verifier, sum_valid)
