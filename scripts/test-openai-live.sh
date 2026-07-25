#!/bin/sh
set -eu

mtl_bin=${MTL_BIN:-./target/release/mtl}
mtl_config=${MTL_CONFIG:-examples/mithril.yaml}
test_model=${MTL_TEST_MODEL:-gpt-5.6-luna}

case "$test_model" in
    *[!A-Za-z0-9._-]*)
        echo "mtl live test: MTL_TEST_MODEL contains unsupported characters" >&2
        exit 1
        ;;
esac
if [ ! -x "$mtl_bin" ]; then
    echo "mtl live test: $mtl_bin is not executable; run scripts/build-macos.sh" >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "mtl live test: curl is required" >&2
    exit 1
fi

"$mtl_bin" run --config "$mtl_config" -- sh -c '
set -eu
test_model=$1
response=$(curl --noproxy "*" -sS "$OPENAI_BASE_URL/responses" \
    -H "content-type: application/json" \
    -H "authorization: Bearer $OPENAI_API_KEY" \
    -d "{\"model\":\"$test_model\",\"input\":\"Reply exactly MITHRIL_OK\",\"reasoning\":{\"effort\":\"none\"},\"max_output_tokens\":32}")

printf "%s\n" "$response"
if printf "%s" "$response" | grep -q '"text"[[:space:]]*:[[:space:]]*"MITHRIL_OK"'; then
    echo "mtl live test: model response received" >&2
    exit 0
fi
if printf "%s" "$response" | grep -q '"code"[[:space:]]*:[[:space:]]*"insufficient_quota"'; then
    echo "mtl live test: OpenAI authenticated the request, but the project has no available quota" >&2
    exit 2
fi

echo "mtl live test: the API returned no successful model response" >&2
exit 1
' mtl-live-test "$test_model"
