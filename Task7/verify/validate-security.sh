#!/bin/bash

NAMESPACE="audit-zone"
FAILED=0

echo ">>> Тест PodSecurity restricted в неймспейсе ${NAMESPACE}"
echo ""

for manifest in secure-manifests/*.yaml; do
  name=$(basename "$manifest")
  path=$(realpath secure-manifests/$name)

  echo ">>> Тест: ${name}"

  if kubectl apply -f $path --dry-run=server 2>&1 | grep -q "Forbidden"; then
    echo "[FAIL] ${name} — запрещён (проблема с PodSecurity!)"
    FAILED=1
  else
    echo "[PASS] ${name} — не запрещён (как и ожидалось)"
  fi
  echo ""
done

echo ">>> Результат:"
if [ "$FAILED" -eq 0 ]; then
  echo "[OK] Все безопасные манифесты работают."
  exit 0
else
  echo "[FAIL] Некоторые безопасные манифесты не работают."
  exit 1
fi
