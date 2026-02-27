load('arc_groups.sage')
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

def MakeRangeProofHelper(statement, nonce, nonce_blinding, presentation_limit, gen_G_var, gen_H_var, rng):
    """
    Add range proof constraints to statement.

    Inputs:
    - statement: LinearRelation statement to which constraints will be added
    - nonce: Integer, the nonce value to prove is in range
    - nonce_blinding: Scalar, the blinding factor for the nonce commitment
    - presentation_limit: Integer, the maximum value of the range (exclusive)
    - gen_G_var: Integer, variable index for generator G
    - gen_H_var: Integer, variable index for generator H
    - rng: Random number generator for creating blinding factors

    Outputs:
    - statement: Modified statement with range proof constraints added
    - D: [Element], array of commitments to the bit decomposition
    - range_witness: [Scalar], witness values for range proof (b[0], s[0], s2[0], b[1], s[1], s2[1], ...)
    """
    # Compute bit decomposition and commitments
    bases = ComputeBases(presentation_limit)

    # Compute bit decomposition of nonce
    b = []
    remainder = nonce
    for base in bases:
        bit_value = 1 if (remainder >= base) else 0
        remainder -= bit_value * base
        b.append(Integer(bit_value))

    # Compute commitments to bits
    D = []
    s = []
    s2 = []
    partial_sum = Integer(0)

    for i in range(len(bases) - 1):
        s_i = G.random_scalar(rng)
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

    # Allocate scalar variables (3 per bit: b, s, s2)
    num_bits = len(b)
    num_scalars = 3 * num_bits
    scalar_vars = statement.allocate_scalars(num_scalars)

    # Unpack into separate arrays
    vars_b = scalar_vars[0::3]      # Every 3rd element starting at 0
    vars_s = scalar_vars[1::3]      # Every 3rd element starting at 1
    vars_s2 = scalar_vars[2::3]     # Every 3rd element starting at 2

    # Allocate and set element variables for bit commitments D
    vars_D = statement.allocate_elements(num_bits)
    statement.set_elements([(vars_D[i], D[i]) for i in range(num_bits)])

    # Add constraints proving each b[i] is in {0,1}
    for i in range(num_bits):
        # D[i] = b[i] * generatorG + s[i] * generatorH
        statement.append_equation(vars_D[i], [(vars_b[i], gen_G_var), (vars_s[i], gen_H_var)])
        # D[i] = b[i] * D[i] + s2[i] * generatorH (proves b[i] is in {0,1})
        statement.append_equation(vars_D[i], [(vars_b[i], vars_D[i]), (vars_s2[i], gen_H_var)])

    # Build witness array: interleave b, s, s2 values
    range_witness = []
    for i in range(num_bits):
        range_witness.extend([b[i], s[i], s2[i]])

    return (statement, D, range_witness)

def VerifyRangeProofHelper(statement, D, nonce_commit, presentation_limit, gen_G_var, gen_H_var):
    """
    Add range proof constraints to statement and verify sum.

    Inputs:
    - statement: LinearRelation statement to which constraints will be added
    - D: [Element], array of commitments to the bit decomposition
    - nonce_commit: Element, the Pedersen commitment to the nonce
    - presentation_limit: Integer, the maximum value of the range (exclusive)
    - gen_G_var: Integer, variable index for generator G
    - gen_H_var: Integer, variable index for generator H

    Outputs:
    - statement: Modified statement with range proof constraints added
    - validity: Boolean, True if sum(bases[i] * D[i]) == nonce_commit, False otherwise
    """
    bases = ComputeBases(presentation_limit)
    num_bits = len(bases)

    # Allocate scalar variables (3 per bit: b, s, s2)
    num_scalars = 3 * num_bits
    scalar_vars = statement.allocate_scalars(num_scalars)

    # Unpack into separate arrays
    vars_b = scalar_vars[0::3]      # Every 3rd element starting at 0
    vars_s = scalar_vars[1::3]      # Every 3rd element starting at 1
    vars_s2 = scalar_vars[2::3]     # Every 3rd element starting at 2

    # Allocate and set element variables for bit commitments D
    vars_D = statement.allocate_elements(num_bits)
    statement.set_elements([(vars_D[i], D[i]) for i in range(num_bits)])

    # Add constraints proving each b[i] is in {0,1}
    for i in range(num_bits):
        # D[i] = b[i] * generatorG + s[i] * generatorH
        statement.append_equation(vars_D[i], [(vars_b[i], gen_G_var), (vars_s[i], gen_H_var)])
        # D[i] = b[i] * D[i] + s2[i] * generatorH
        statement.append_equation(vars_D[i], [(vars_b[i], vars_D[i]), (vars_s2[i], gen_H_var)])

    # Verify the sum check: nonce_commit == sum(bases[i] * D[i])
    # This is done explicitly by computing the sum homomorphically
    sum_D = G.identity()
    for i in range(len(bases)):
        sum_D = sum_D + Integer(bases[i]) * D[i]

    sum_valid = (sum_D == nonce_commit)
    return (statement, sum_valid)
