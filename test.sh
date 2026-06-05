#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PASS=0
FAIL=0
ERRORS=""

run_project() {
    local name="$1"
    local path="$2"

    echo ""
    echo "========================================"
    echo "  $name"
    echo "========================================"
    cd "$path"

    local out
    out=$(nargo test 2>&1)
    local exit_code=$?

    # Mostrar warnings y errores relevantes
    echo "$out" | grep -E "^warning|^error|Testing.*ok|Testing.*FAILED|tests passed|FAILED" || true

    local passed
    passed=$(echo "$out" | grep -c "ok$" || true)
    local failed
    failed=$(echo "$out" | grep -c "FAILED$" || true)

    PASS=$((PASS + passed))

    if [ "$exit_code" -ne 0 ] || [ "$failed" -gt 0 ]; then
        FAIL=$((FAIL + failed))
        ERRORS="$ERRORS\n  [FALLO] $name ($failed tests fallidos)"
        echo ""
        echo "--- Detalle de fallos ---"
        echo "$out" | grep "FAILED" || true
    fi

    cd "$ROOT"
}

echo ""
echo "ZK-Bridge-Zero — Suite de tests"
echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"

run_project "noir-bigint-bls12_381" "$ROOT/noir-bigint-bls12_381"
run_project "noir-bls-signature"    "$ROOT/noir-bls-signature"

echo ""
echo "========================================"
echo "  RESUMEN"
echo "========================================"
echo "  Tests pasados : $PASS"
echo "  Tests fallidos: $FAIL"

if [ "$FAIL" -eq 0 ]; then
    echo "  Estado        : TODO VERDE"
else
    echo "  Estado        : HAY FALLOS"
    echo -e "$ERRORS"
    exit 1
fi
