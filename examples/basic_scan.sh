#!/bin/bash
# Basic PromptScan usage examples

echo "=== PromptScan Basic Usage Examples ==="
echo ""

# Example 1: Simple scan
echo "1. Simple scan (no authentication):"
echo "   promptscan test https://api.example.com/chat"
echo ""

# Example 2: With API key
echo "2. Scan with API key authentication:"
echo "   promptscan test https://api.example.com/chat --api-key YOUR_API_KEY"
echo ""

# Example 3: With Bearer token
echo "3. Scan with Bearer token:"
echo "   promptscan test https://api.example.com/chat --bearer-token YOUR_TOKEN"
echo ""

# Example 4: Generate JSON report
echo "4. Generate JSON report:"
echo "   promptscan test https://api.example.com/chat -o json -r report.json"
echo ""

# Example 5: Generate HTML report
echo "5. Generate HTML report:"
echo "   promptscan test https://api.example.com/chat -o html -r report.html"
echo ""

# Example 6: Verbose output
echo "6. Verbose output for debugging:"
echo "   promptscan test https://api.example.com/chat -v"
echo ""

# Example 7: Custom timeout
echo "7. Custom timeout (60 seconds):"
echo "   promptscan test https://api.example.com/chat --timeout 60"
echo ""

# Example 8: List available payloads
echo "8. List available payload categories:"
echo "   promptscan list-payloads"
echo ""

# Example 9: Get tool information
echo "9. Display tool information:"
echo "   promptscan info"
echo ""

echo "=== End of Examples ==="
