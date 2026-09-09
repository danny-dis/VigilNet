#!/usr/bin/env bash
# Script to identify and fix unwrap() calls in the codebase

set -e

echo "=== VigilNet unwrap() Fixer ==="
echo ""

# Count unwrap() by crate
echo "unwrap() count by crate:"
echo "========================"
for crate in crates/*/; do
    crate_name=$(basename "$crate")
    count=$(grep -r "\.unwrap()" "$crate/src" --include="*.rs" 2>/dev/null | grep -v "#\[cfg(test)\]" | wc -l)
    printf "%-30s %4d\n" "$crate_name" "$count"
done

echo ""
echo "Total unwrap() in production code:"
grep -r "\.unwrap()" crates/ --include="*.rs" | grep -v "#\[cfg(test)\]" | wc -l

echo ""
echo "To fix unwrap() calls:"
echo "1. Run: ./scripts/fix_unwrap.sh <crate-name>"
echo "2. Review each occurrence and replace with proper error handling"
echo "3. Use '?' operator for Result/Option propagation"
echo "4. Use 'ok_or()' or 'ok_or_else()' to convert to custom errors"
echo ""
echo "Common patterns:"
echo "  .unwrap() -> .ok_or(Error::NotFound)?"
echo "  .unwrap() -> .map_err(|e| Error::Other(e))?"
echo "  .unwrap() -> match statement with proper error handling"
