# TRAILING_TAB_ENCODED Bypass Technique

## Overview
The TRAILING_TAB_ENCODED technique involves adding a URL-encoded tab character (%09) at the end of the URL path. This bypasses certain web application firewalls or URL validation mechanisms that don't properly handle URL-encoded whitespace characters.

## Technical Details
- **Method**: URL Path Manipulation
- **Character**: Tab (\t)
- **Encoding**: URL-encoded (%09)
- **Position**: End of URL path

## Example
Original URL: `https://bypass403.vercel.app/admin`
Bypassed URL: `https://bypass403.vercel.app/admin%09/`

## How to Test
### Using curl
```bash
curl -X GET "https://bypass403.vercel.app/admin%09/" \
     -H "User-Agent: Mozilla/5.0" \
     -H "Accept: text/html"
```

### Using Burp Suite
1. Intercept the request in Burp
2. Add `%09` at the end of the path before the final slash
3. Forward the request

## Security Implications
This technique can bypass:
- URL validation that doesn't handle URL-encoded whitespace
- WAF rules that don't normalize URL-encoded characters
- Path traversal protections

## Recommendations for Defenders
- Implement proper URL normalization
- Decode URL-encoded characters before validation
- Enforce strict path validation
- Use security headers like X-Content-Type-Options

## Related Techniques
- TRAILING_SPACE_ENCODED
- TRAILING_SEMICOLON_SLASH
- BACKSLASH_ENCODED
