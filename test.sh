#!/bin/bash
# Manual smoke test — start the app first (mvn spring-boot:run), then run this script.
# Covers all six phases. Requires curl + python3 (used for JSON parsing/pretty-print).
BASE="http://localhost:8080"
AUTH="-u admin:pqc-demo"

echo "=== A: Classical ==="
curl -s $AUTH $BASE/api/pqc/status | python3 -m json.tool | grep cipherMode

echo "=== B: PQC Only ==="
curl -s $AUTH -H "X-PQC-Supported: Kyber-768" $BASE/api/pqc/status | python3 -m json.tool | grep cipherMode

echo "=== C: Hybrid ==="
curl -s $AUTH -H "X-PQC-Supported: Kyber-768" -H "X-PQC-Hybrid: true" $BASE/api/pqc/status | python3 -m json.tool | grep cipherMode

echo "=== D: Upgrade Demo ==="
curl -s $AUTH $BASE/api/pqc/upgrade-demo | python3 -m json.tool | grep upgraded

echo "=== E: Dilithium Sign ==="
curl -s $AUTH -X POST "$BASE/api/pqc/sign?message=test" | python3 -m json.tool | grep -E "verified|signatureBytes"

echo "=== F: SPHINCS+ Sign ==="
curl -s $AUTH -X POST "$BASE/api/pqc/sign-sphincs?message=test" | python3 -m json.tool | grep -E "verified|signatureBytes"

echo "=== G: Actuator (keyManagement is null unless Phase 3 / KMS is configured) ==="
curl -s $AUTH $BASE/actuator/pqc | python3 -m json.tool | grep -E "totalSessions|quantumSafetyPercent|keyManagement"

echo "=== H: JWT — Issue token (Phase 4) ==="
TOKEN=$(curl -s -X POST "$BASE/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret"}' | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])")
echo "Token issued (${#TOKEN} chars)"

echo "=== I: JWT — Access protected resource with token ==="
curl -s "$BASE/api/secure" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | grep -E "message|quantumSafe"

echo "=== J: JWT — Rejected without a token (expect 403 — httpBasic/formLogin are disabled, so there's no 401 challenge entry point) ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" "$BASE/api/secure"

echo "=== K: Migration Bridge — bridge-handshake (Phase 5) ==="
curl -s $AUTH -X POST "$BASE/api/migration/bridge-handshake?clientId=smoke-test" | python3 -m json.tool | grep -E "negotiatedCipherMode|quantumSafe"

echo "=== L: Migration Bridge — simulate legacy RSA peer ==="
curl -s $AUTH -X POST "$BASE/api/migration/simulate-legacy?clientId=legacy-smoke" | python3 -m json.tool | grep -E "negotiatedCipherMode|quantumSafe"

echo "=== M: Migration Bridge — status ==="
curl -s $AUTH "$BASE/api/migration/status" | python3 -m json.tool | grep -E "totalSessions|pqcMigrationPercent"

echo "=== N: Data at Rest — encrypt field (Phase 6) ==="
ENCODED=$(curl -s $AUTH -X POST "$BASE/api/atrest/encrypt-field" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"123-45-6789","recordId":"smoke-test","fieldName":"ssn"}' | python3 -c "import sys, json; print(json.load(sys.stdin)['encoded'])")
echo "Encoded: $ENCODED"

echo "=== O: Data at Rest — decrypt field (must recover the original plaintext) ==="
curl -s $AUTH -X POST "$BASE/api/atrest/decrypt-field" \
  -H "Content-Type: application/json" \
  -d "{\"encoded\":\"$ENCODED\",\"recordId\":\"smoke-test\",\"fieldName\":\"ssn\"}" | python3 -m json.tool

echo "=== P: Data at Rest — status ==="
curl -s $AUTH "$BASE/api/atrest/status" | python3 -m json.tool
