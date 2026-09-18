import sys
sys.path.append('backend')
from app.suites.suite4_crypto import run_suite4_tool

print("--- Testing Stego Detection & Encoding ---")
# 1. Stego Encode
res_encode = run_suite4_tool('stego_detector', '', {'mode': 'encode', 'secret_text': 'SECRET_MISSION_ALPHA_77', 'payload_type': 'text'})
assert res_encode.generated_payload.startswith('data:image/png;base64,'), 'Encode failed'
assert res_encode.extracted_secret == 'SECRET_MISSION_ALPHA_77', 'Extracted secret mismatch on encode'
print('[PASS] Stego Encode generated PNG Data URL payload')

# 2. Stego Decode
res_decode = run_suite4_tool('stego_detector', res_encode.generated_payload, {'mode': 'analyze'})
assert 'SECRET_MISSION_ALPHA_77' in (res_decode.extracted_secret or ''), f'Decode failed: {res_decode.extracted_secret}'
print(f'[PASS] Stego Decode extracted secret: {res_decode.extracted_secret}')

print("\n--- Testing AES-256-GCM Dual Mode ---")
# 3. AES Encrypt
res_enc = run_suite4_tool('aes_gcm_suite', 'TopSecretPassword123!', {'mode': 'encrypt'})
assert res_enc.generated_payload, 'AES Encrypt failed'
print(f'[PASS] AES Encrypt generated ciphertext hex: {res_enc.generated_payload[:24]}...')

# 4. AES Decrypt
res_dec = run_suite4_tool('aes_gcm_suite', res_enc.extracted_secret, {'mode': 'decrypt'})
assert res_dec.extracted_secret == 'TopSecretPassword123!', f'Decryption mismatch: {res_dec.extracted_secret}'
print(f'[PASS] AES Decrypt recovered plaintext: {res_dec.extracted_secret}')

print("\n--- Testing Crypto Hasher & Speed Benchmark ---")
# 5. Crypto Benchmark (without provided output - computes actual hash)
res_bench1 = run_suite4_tool('crypto_benchmark', 'Algorithm: SHA-256, Input: "test data"', {})
assert res_bench1.generated_payload == '916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9', f'Computed hash mismatch: {res_bench1.generated_payload}'
print(f'[PASS] Crypto Benchmark computed hash for "test data": {res_bench1.generated_payload}')

# 6. Crypto Benchmark (with user testcase containing provided hash)
user_tc = 'Algorithm: SHA-256, Input: "test data", Output: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
res_bench2 = run_suite4_tool('crypto_benchmark', user_tc, {})
assert res_bench2.generated_payload == '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'User testcase hash mismatch'
print(f'[PASS] Crypto Benchmark handled user testcase hash: {res_bench2.generated_payload}')

print("\nALL VERIFICATIONS PASSED 100%!")
