
#!/bin/bash

echo "BypassX Go Tool - Comprehensive Endpoint Testing"
echo "================================================"

# Build the tool
echo "[INFO] Building bypassx tool..."
go build -o bypassx .

if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to build bypassx tool"
    exit 1
fi

echo "[INFO] Tool built successfully"
echo ""

# List of all lab endpoints to test
endpoints=(
    "/admin"
    "/api/admin" 
    "/secure"
    "/internal"
    "/debug"
    "/advanced"
    "/waf"
    "/cdn"
    "/method-override"
    "/http-version"
    "/connect-method"
    "/path-normalization"
    "/null-bytes"
    "/path-params"
    "/fragment-bypass"
    "/header-pollution"
    "/xff-pollution"
    "/host-injection"
    "/request-smuggling"
    "/lb-bypass"
    "/nginx-bypass"
    "/apache-bypass"
    "/haproxy-bypass"
    "/content-type"
    "/accept-bypass"
    "/charset-bypass"
    "/session-bypass"
    "/cookie-bypass"
    "/token-bypass"
    "/rate-limit-bypass"
    "/geo-bypass"
    "/ip-whitelist"
    "/extension-bypass.txt"
    "/mime-bypass"
    "/cache-bypass"
    "/cdn-origin"
    "/csp-bypass"
    "/csrf-bypass"
    "/double-encode"
    "/mixed-encode"
    "/unicode-bypass"
    "/docker-bypass"
    "/k8s-bypass"
    "/istio-bypass"
)

total_endpoints=${#endpoints[@]}
successful_endpoints=0
total_bypasses=0

echo "[INFO] Testing $total_endpoints endpoints with bypassx..."
echo ""

# Test each endpoint
for endpoint in "${endpoints[@]}"; do
    echo "Testing endpoint: $endpoint"
    echo "----------------------------------------"
    
    # Run bypassx against the endpoint
    result=$(./bypassx -u "http://127.0.0.1:5000$endpoint" -all -status "200,302,401" 2>&1)
    
    # Count successful bypasses from output
    bypasses=$(echo "$result" | grep -c "\[BYPASS SUCCESS\]")
    
    if [ $bypasses -gt 0 ]; then
        echo "✓ SUCCESS: Found $bypasses bypasses"
        successful_endpoints=$((successful_endpoints + 1))
        total_bypasses=$((total_bypasses + bypasses))
        
        # Show the successful techniques
        echo "$result" | grep "\[BYPASS SUCCESS\]" | head -5
        if [ $bypasses -gt 5 ]; then
            echo "... and $((bypasses - 5)) more bypasses"
        fi
    else
        echo "✗ FAILED: No bypasses found"
    fi
    
    echo ""
    sleep 0.5  # Small delay between tests
done

# Summary
echo "================================================"
echo "COMPREHENSIVE TEST SUMMARY"
echo "================================================"
echo "Total endpoints tested: $total_endpoints"
echo "Endpoints with bypasses: $successful_endpoints"
echo "Total bypasses found: $total_bypasses"
echo "Success rate: $(( successful_endpoints * 100 / total_endpoints ))%"
echo ""

if [ $successful_endpoints -eq $total_endpoints ]; then
    echo "🎉 ALL ENDPOINTS SUCCESSFULLY BYPASSED!"
    echo "BypassX tool is working perfectly with the lab"
else
    echo "⚠️  Some endpoints may need additional bypass techniques"
fi

echo ""
echo "For detailed results, check individual endpoint tests above"
