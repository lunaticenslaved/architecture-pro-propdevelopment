#!/bin/bash

NAMESPACE="audit-zone"
FAILED=0

echo ">>> Тест PodSecurity restricted в неймспейсе ${NAMESPACE}"
echo ""

for manifest in insecure-manifests/*.yaml; do
  name=$(basename "$manifest")
  path=$(realpath insecure-manifests/$name)

  echo ">>> Тест: ${name}"

  if kubectl apply -f $path --dry-run=server 2>&1 | grep -q "Forbidden"; then
    echo "[PASS] ${name} — запрещён (как и ожидалось)"
  else
    echo "[FAIL] ${name} — НЕ ЗАПРЕЩЁН (проблема с PodSecurity!)"
    FAILED=1
  fi
  echo ""
done

echo ">>> Результат:"
if [ "$FAILED" -eq 0 ]; then
  echo "[OK] Все небезопасные манифесты ЗАПРЕЩЕНЫ. PodSecurity работает."
  exit 0
else
  echo "[FAIL] Некоторые манифесты ПРОПУЩЕНЫ. PodSecurity не работает!"
  exit 1
fi
