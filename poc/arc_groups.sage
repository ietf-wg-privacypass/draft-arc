import sys
import os
import hashlib

# IMPORTANT: Add sigma/poc to Python path FIRST, before current directory
# This ensures we import from sigma/poc/sagelib, not the old local sagelib
sigma_poc_path = os.path.join(os.getcwd(), 'sigma', 'poc')
if sigma_poc_path not in sys.path:
    sys.path.insert(0, sigma_poc_path)

# Add current directory to Python path for util module (AFTER sigma/poc)
if os.getcwd() not in sys.path:
    sys.path.append(os.getcwd())

from sagelib.groups import GroupP256
from sagelib.hash_to_field import XMDExpander, hash_to_field
from sagelib.h2c_suite import BasicH2CSuiteDef, BasicH2CSuite
from sagelib.sswu_generic import GenericSSWU
from util import to_bytes

G = GroupP256()

context_string = b"ARCV1-P256"

# Get P256 parameters from the Group
p = G.p
F = G.F
A = G.a
B = G.b
order = G.group_order

# Create a hash-to-curve suite that we'll reuse (matching old implementation)
k = 128
L = 48
H = hashlib.sha256
m = 1  # field degree for P256 (prime field, not extension)

# Create with a placeholder DST that we'll override
placeholder_dst = b"placeholder"
expander_template = XMDExpander(placeholder_dst, H, k)
suite_def = BasicH2CSuiteDef("ARC P-256", F, A, B, expander_template, H, L, GenericSSWU, 1, k, True, placeholder_dst)
h2c_suite = BasicH2CSuite("ARC-P256-HashToGroup", suite_def)

def _hash_to_group_with_dst(msg, dst):
    """Internal: hash to group with explicit DST"""
    h2c_suite.expand._dst = dst
    return h2c_suite(msg)

def _hash_to_scalar_with_dst(msg, dst):
    """Internal: hash to scalar with explicit DST"""
    expander = XMDExpander(dst, H, k)
    return hash_to_field(msg, 1, order, m, L, expander)[0][0]

def hash_to_group(x, info):
    """Hash to group, constructing DST from context_string + info"""
    dst = to_bytes("HashToGroup-") + to_bytes(context_string) + info
    return _hash_to_group_with_dst(x, dst)

def hash_to_scalar(x, info):
    """Hash to scalar, constructing DST from context_string + info"""
    dst = to_bytes("HashToScalar-") + to_bytes(context_string) + info
    return _hash_to_scalar_with_dst(x, dst)

GenG = G.generator()
GenH = hash_to_group(G.serialize([GenG]), to_bytes("generatorH"))
