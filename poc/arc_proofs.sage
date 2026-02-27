import sys
import os

# Add sigma/poc to Python path so we can import from it
sigma_poc_path = os.path.join(os.getcwd(), 'sigma', 'poc')
if sigma_poc_path not in sys.path:
    sys.path.insert(0, sigma_poc_path)

# Load arc_groups to get G, GenG, GenH, hash functions, and context_string
load('arc_groups.sage')
# Load range_proof to get the range proof helpers
load('range_proof.sage')
# Load ciphersuite to get NISchnorrProofShake128P256
load('ciphersuite_arc.sage')

from sagelib.sigma_protocols import LinearRelation, CSRNG
from util import to_bytes

class DeterministicRNG(CSRNG):
    """Wrapper to use ARC's RNG with sigma protocol CSRNG interface"""
    def __init__(self, rng):
        self.rng = rng

    def random_scalar(self):
        return G.random_scalar(self.rng)

class CredentialRequestProof(object):
    @classmethod
    def prove(cls, m1, m2, r1, r2, m1_enc, m2_enc, rng, vectors):
        # Create linear relation statement
        statement = LinearRelation(G)

        # Allocate scalar variables (4 scalars)
        [m1_var, m2_var, r1_var, r2_var] = statement.allocate_scalars(4)

        # Build witness array
        witness = [m1, m2, r1, r2]

        # Allocate and set element variables (4 elements)
        [gen_G_var, gen_H_var, m1_enc_var, m2_enc_var] = statement.allocate_elements(4)
        statement.set_elements([
            (gen_G_var, GenG),
            (gen_H_var, GenH),
            (m1_enc_var, m1_enc),
            (m2_enc_var, m2_enc)
        ])

        # Add constraints
        # m1_enc = m1 * genG + r1 * genH
        statement.append_equation(m1_enc_var, [(m1_var, gen_G_var), (r1_var, gen_H_var)])
        # m2_enc = m2 * genG + r2 * genH
        statement.append_equation(m2_enc_var, [(m2_var, gen_G_var), (r2_var, gen_H_var)])

        # Create prover with session ID and statement
        session_id = context_string + "CredentialRequest"
        prover = NISchnorrProofShake128P256(session_id, statement)

        # Generate proof
        csrng = DeterministicRNG(rng)
        return prover.prove(witness, csrng)

    @classmethod
    def verify(cls, blinded_request):
        # Create linear relation statement
        statement = LinearRelation(G)

        # Allocate scalar variables (4 scalars)
        [m1_var, m2_var, r1_var, r2_var] = statement.allocate_scalars(4)

        # Allocate and set element variables (4 elements)
        [gen_G_var, gen_H_var, m1_enc_var, m2_enc_var] = statement.allocate_elements(4)
        statement.set_elements([
            (gen_G_var, GenG),
            (gen_H_var, GenH),
            (m1_enc_var, blinded_request.m1_enc),
            (m2_enc_var, blinded_request.m2_enc)
        ])

        # Add constraints
        # m1_enc = m1 * genG + r1 * genH
        statement.append_equation(m1_enc_var, [(m1_var, gen_G_var), (r1_var, gen_H_var)])
        # m2_enc = m2 * genG + r2 * genH
        statement.append_equation(m2_enc_var, [(m2_var, gen_G_var), (r2_var, gen_H_var)])

        # Create verifier with session ID and statement
        session_id = context_string + "CredentialRequest"
        verifier = NISchnorrProofShake128P256(session_id, statement)

        # Verify proof
        return verifier.verify(blinded_request.request_proof)

class CredentialResponseProof(object):
    @classmethod
    def prove(cls, private_key, public_key, request, b, U, enc_U_prime, X0_aux, X1_aux, X2_aux, H_aux, rng, vectors):
        # Create linear relation statement
        statement = LinearRelation(G)

        # Allocate scalar variables (7 scalars)
        [x0_var, x1_var, x2_var, xb_var, b_var, t1_var, t2_var] = statement.allocate_scalars(7)

        # Build witness array
        t1 = b * private_key.x1
        t2 = b * private_key.x2
        witness = [private_key.x0, private_key.x1, private_key.x2, private_key.xb, b, t1, t2]

        # Allocate and set element variables (13 elements)
        [gen_G_var, gen_H_var, m1_enc_var, m2_enc_var, U_var, enc_U_prime_var,
         X0_var, X1_var, X2_var, X0_aux_var, X1_aux_var, X2_aux_var, H_aux_var] = statement.allocate_elements(13)
        statement.set_elements([
            (gen_G_var, GenG),
            (gen_H_var, GenH),
            (m1_enc_var, request.m1_enc),
            (m2_enc_var, request.m2_enc),
            (U_var, U),
            (enc_U_prime_var, enc_U_prime),
            (X0_var, public_key.X0),
            (X1_var, public_key.X1),
            (X2_var, public_key.X2),
            (X0_aux_var, X0_aux),
            (X1_aux_var, X1_aux),
            (X2_aux_var, X2_aux),
            (H_aux_var, H_aux)
        ])

        # Add constraints
        # 1. X0 = x0 * generatorG + x0Blinding * generatorH
        statement.append_equation(X0_var, [(x0_var, gen_G_var), (xb_var, gen_H_var)])

        # 2. X1 = x1 * generatorH
        statement.append_equation(X1_var, [(x1_var, gen_H_var)])

        # 3. X2 = x2 * generatorH
        statement.append_equation(X2_var, [(x2_var, gen_H_var)])

        # 4. X0Aux = b * x0Blinding * generatorH
        # 4a. HAux = b * generatorH
        statement.append_equation(H_aux_var, [(b_var, gen_H_var)])
        # 4b: X0Aux = x0Blinding * HAux (= b * x0Blinding * generatorH)
        statement.append_equation(X0_aux_var, [(xb_var, H_aux_var)])

        # 5. X1Aux = b * x1 * generatorH
        # 5a. X1Aux = t1 * generatorH (t1 = b * x1)
        statement.append_equation(X1_aux_var, [(t1_var, gen_H_var)])
        # 5b. X1Aux = b * X1 (X1 = x1 * generatorH)
        statement.append_equation(X1_aux_var, [(b_var, X1_var)])

        # 6. X2Aux = b * x2 * generatorH
        # 6a. X2Aux = b * X2 (X2 = x2 * generatorH)
        statement.append_equation(X2_aux_var, [(b_var, X2_var)])
        # 6b. X2Aux = t2 * H (t2 = b * x2)
        statement.append_equation(X2_aux_var, [(t2_var, gen_H_var)])

        # 7. U = b * generatorG
        statement.append_equation(U_var, [(b_var, gen_G_var)])
        # 8. encUPrime = b * (X0 + x1 * Enc(m1) + x2 * Enc(m2))
        # simplified: encUPrime = b * X0 + t1 * m1Enc + t2 * m2Enc, since t1 = b * x1 and t2 = b * x2
        statement.append_equation(enc_U_prime_var, [(b_var, X0_var), (t1_var, m1_enc_var), (t2_var, m2_enc_var)])

        # Create prover with session ID and statement
        session_id = context_string + "CredentialResponse"
        prover = NISchnorrProofShake128P256(session_id, statement)

        # Generate proof
        csrng = DeterministicRNG(rng)
        return prover.prove(witness, csrng)

    @classmethod
    def verify(cls, public_key, response, request):
        # Create linear relation statement
        statement = LinearRelation(G)

        # Allocate scalar variables (7 scalars)
        [x0_var, x1_var, x2_var, xb_var, b_var, t1_var, t2_var] = statement.allocate_scalars(7)

        # Allocate and set element variables (13 elements)
        [gen_G_var, gen_H_var, m1_enc_var, m2_enc_var, U_var, enc_U_prime_var,
         X0_var, X1_var, X2_var, X0_aux_var, X1_aux_var, X2_aux_var, H_aux_var] = statement.allocate_elements(13)
        statement.set_elements([
            (gen_G_var, GenG),
            (gen_H_var, GenH),
            (m1_enc_var, request.m1_enc),
            (m2_enc_var, request.m2_enc),
            (U_var, response.U),
            (enc_U_prime_var, response.enc_U_prime),
            (X0_var, public_key.X0),
            (X1_var, public_key.X1),
            (X2_var, public_key.X2),
            (X0_aux_var, response.X0_aux),
            (X1_aux_var, response.X1_aux),
            (X2_aux_var, response.X2_aux),
            (H_aux_var, response.H_aux)
        ])

        # Add constraints
        # 1. X0 = x0 * generatorG + x0Blinding * generatorH
        statement.append_equation(X0_var, [(x0_var, gen_G_var), (xb_var, gen_H_var)])

        # 2. X1 = x1 * generatorH
        statement.append_equation(X1_var, [(x1_var, gen_H_var)])

        # 3. X2 = x2 * generatorH
        statement.append_equation(X2_var, [(x2_var, gen_H_var)])

        # 4. X0Aux = b * x0Blinding * generatorH
        # 4a. HAux = b * generatorH
        statement.append_equation(H_aux_var, [(b_var, gen_H_var)])
        # 4b: X0Aux = x0Blinding * HAux (= b * x0Blinding * generatorH)
        statement.append_equation(X0_aux_var, [(xb_var, H_aux_var)])

        # 5. X1Aux = b * x1 * generatorH
        # 5a. X1Aux = t1 * generatorH (t1 = b * x1)
        statement.append_equation(X1_aux_var, [(t1_var, gen_H_var)])
        # 5b. X1Aux = b * X1 (X1 = x1 * generatorH)
        statement.append_equation(X1_aux_var, [(b_var, X1_var)])

        # 6. X2Aux = b * x2 * generatorH
        # 6a. X2Aux = b * X2 (X2 = x2 * generatorH)
        statement.append_equation(X2_aux_var, [(b_var, X2_var)])
        # 6b. X2Aux = t2 * H (t2 = b * x2)
        statement.append_equation(X2_aux_var, [(t2_var, gen_H_var)])

        # 7. U = b * generatorG
        statement.append_equation(U_var, [(b_var, gen_G_var)])
        # 8. encUPrime = b * (X0 + x1 * Enc(m1) + x2 * Enc(m2))
        # simplified: encUPrime = b * X0 + t1 * m1Enc + t2 * m2Enc, since t1 = b * x1 and t2 = b * x2
        statement.append_equation(enc_U_prime_var, [(b_var, X0_var), (t1_var, m1_enc_var), (t2_var, m2_enc_var)])

        # Create verifier with session ID and statement
        session_id = context_string + "CredentialResponse"
        verifier = NISchnorrProofShake128P256(session_id, statement)

        # Verify proof
        return verifier.verify(response.response_proof)

class PresentationProof(object):
    def __init__(self, D, challenge, responses):
        self.D = D
        self.challenge = challenge
        self.responses = responses

    def serialize(self):
        # Serialize D array first, then challenge, then responses
        output = b''
        for D_i in self.D:
            output += G.serialize([D_i])
        output += G.ScalarField.serialize([self.challenge])
        for response in self.responses:
            output += G.ScalarField.serialize([response])
        return output

    @classmethod
    def prove(cls, U, U_prime_commit, m1_commit, tag, generator_T, credential, V, r, z, nonce, nonce_blinding, nonce_commit, presentation_limit, rng, vectors):
        # Create linear relation statement
        statement = LinearRelation(G)

        # Allocate scalar variables for presentation (5 scalars)
        [m1_var, z_var, r_neg_var, nonce_var, nonce_blinding_var] = statement.allocate_scalars(5)

        # Build presentation witness array (5 scalars)
        presentation_witness = [credential.m1, z, -r, nonce, nonce_blinding]

        # Allocate and set element variables for presentation (10 elements)
        [gen_G_var, gen_H_var, U_var, U_prime_commit_var, m1_commit_var,
         V_var, X1_var, tag_var, gen_T_var, nonce_commit_var] = statement.allocate_elements(10)
        statement.set_elements([
            (gen_G_var, GenG),
            (gen_H_var, GenH),
            (U_var, U),
            (U_prime_commit_var, U_prime_commit),
            (m1_commit_var, m1_commit),
            (V_var, V),
            (X1_var, credential.X1),
            (tag_var, tag),
            (gen_T_var, generator_T),
            (nonce_commit_var, nonce_commit)
        ])

        # Add presentation constraints (4 constraints)
        # 1. m1Commit = m1 * U + z * generatorH
        statement.append_equation(m1_commit_var, [(m1_var, U_var), (z_var, gen_H_var)])
        # 2. V = z * X1 - r * generatorG
        statement.append_equation(V_var, [(z_var, X1_var), (r_neg_var, gen_G_var)])
        # 3. nonceCommit = nonce * generatorG + nonceBlinding * generatorH
        statement.append_equation(nonce_commit_var, [(nonce_var, gen_G_var), (nonce_blinding_var, gen_H_var)])
        # 4. G.HashToGroup(presentationContext, "Tag") = m1 * tag + nonce * tag
        statement.append_equation(gen_T_var, [(m1_var, tag_var), (nonce_var, tag_var)])

        # 5. Add range proof constraints
        (statement, D, range_witness) = MakeRangeProofHelper(statement, nonce, nonce_blinding, presentation_limit, gen_G_var, gen_H_var, rng)

        # Combine witnesses: presentation (5) + range (3*k where k is number of bits)
        witness = presentation_witness + range_witness

        # Create prover with session ID and statement
        session_id = context_string + "CredentialPresentation"
        prover = NISchnorrProofShake128P256(session_id, statement)

        # Generate proof
        csrng = DeterministicRNG(rng)
        proof_bytes = prover.prove(witness, csrng)

        # Parse proof bytes to extract challenge and responses
        # Format: challenge (scalar_len bytes) + responses (num_witness * scalar_len bytes)
        scalar_len = G.ScalarField.scalar_byte_length()
        challenge_bytes = proof_bytes[:scalar_len]
        responses_bytes = proof_bytes[scalar_len:]

        challenge = G.ScalarField.deserialize(challenge_bytes)[0]

        # Deserialize responses
        num_responses = len(witness)
        responses = []
        for i in range(num_responses):
            resp_bytes = responses_bytes[i*scalar_len:(i+1)*scalar_len]
            responses.append(G.ScalarField.deserialize(resp_bytes)[0])

        # Return PresentationProof object containing D, challenge, and responses
        return cls(D, challenge, responses)

    @classmethod
    def verify(cls, server_private_key, server_public_key, request_context, presentation_context, presentation, presentation_limit):
        # Create linear relation statement
        statement = LinearRelation(G)

        # Compute verification values
        m2 = hash_to_scalar(request_context, to_bytes("requestContext"))
        V = server_private_key.x0 * presentation.U + server_private_key.x1 * presentation.m1_commit + server_private_key.x2 * m2 * presentation.U - presentation.U_prime_commit
        generator_T = hash_to_group(presentation_context, to_bytes("Tag"))

        # Allocate scalar variables for presentation (5 scalars)
        [m1_var, z_var, r_neg_var, nonce_var, nonce_blinding_var] = statement.allocate_scalars(5)

        # Allocate and set element variables for presentation (10 elements)
        [gen_G_var, gen_H_var, U_var, U_prime_commit_var, m1_commit_var,
         V_var, X1_var, tag_var, gen_T_var, nonce_commit_var] = statement.allocate_elements(10)
        statement.set_elements([
            (gen_G_var, GenG),
            (gen_H_var, GenH),
            (U_var, presentation.U),
            (U_prime_commit_var, presentation.U_prime_commit),
            (m1_commit_var, presentation.m1_commit),
            (V_var, V),
            (X1_var, server_public_key.X1),
            (tag_var, presentation.tag),
            (gen_T_var, generator_T),
            (nonce_commit_var, presentation.nonce_commit)
        ])

        # Add presentation constraints (4 constraints)
        # 1. m1Commit = m1 * U + z * generatorH
        statement.append_equation(m1_commit_var, [(m1_var, U_var), (z_var, gen_H_var)])
        # 2. V = z * X1 - r * generatorG
        statement.append_equation(V_var, [(z_var, X1_var), (r_neg_var, gen_G_var)])
        # 3. nonceCommit = nonce * generatorG + nonceBlinding * generatorH
        statement.append_equation(nonce_commit_var, [(nonce_var, gen_G_var), (nonce_blinding_var, gen_H_var)])
        # 4. G.HashToGroup(presentationContext, "Tag") = m1 * tag + nonce * tag
        statement.append_equation(gen_T_var, [(m1_var, tag_var), (nonce_var, tag_var)])

        # 5. Add range proof constraints and verify the sum of the nonceCommit bit commitments
        (statement, sum_valid) = VerifyRangeProofHelper(statement, presentation.proof.D, presentation.nonce_commit, presentation_limit, gen_G_var, gen_H_var)

        # Create proof bytes from challenge and responses
        proof_bytes = b''
        proof_bytes += G.ScalarField.serialize([presentation.proof.challenge])
        for response in presentation.proof.responses:
            proof_bytes += G.ScalarField.serialize([response])

        # Create verifier with session ID and statement
        session_id = context_string + "CredentialPresentation"
        verifier = NISchnorrProofShake128P256(session_id, statement)

        # Verify the joint proof
        proof_valid = sum_valid and verifier.verify(proof_bytes)
        return proof_valid
