# Comparison with Existing Tools

## Feature Comparison

| Feature                | har-capture | DevTools¹ | Google² | Cloudflare³ | Edgio⁴ |
| ---------------------- | ----------- | --------- | ------- | ----------- | ------ |
| **Sanitization**       |             |           |         |             |        |
| Cookies/auth headers   | ✅          | ✅        | ✅      | ✅          | ✅     |
| IPs, MACs, emails      | ✅          | ❌        | ❌      | ❌          | ❌     |
| Passwords in forms     | ✅          | ❌        | ✅      | ❌          | ✅     |
| JWT smart redaction    | ❌          | ❌        | ❌      | ✅          | ❌     |
| Correlation-preserving | ✅          | ❌        | ❌      | ❌          | ❌     |
| **Usability**          |             |           |         |             |        |
| No installation needed | ❌          | ✅        | ❌      | ✅          | ✅     |
| Data stays local       | ✅          | ✅        | ❌      | ✅          | ✅     |
| CLI/scriptable         | ✅          | ❌        | ✅      | ❌          | ✅     |
| Interactive review     | ✅          | ❌        | ✅      | ❌          | ❌     |
| **Extras**             |             |           |         |             |        |
| Integrated capture     | ✅          | ✅        | ❌      | ❌          | ❌     |
| Custom patterns        | ✅          | ❌        | ✅      | ❌          | ❌     |
| Validation             | ✅          | ❌        | ❌      | ❌          | ❌     |

## Tool Details

### 1. Chrome DevTools

[Chrome DevTools Network Reference](https://developer.chrome.com/docs/devtools/network/reference)

**Pros:**

- Built into browser (no installation)
- [v130+](https://developer.chrome.com/blog/new-in-devtools-130) sanitizes cookies and auth headers by default

**Cons:**

- Only sanitizes cookies and auth headers
- No CLI or automation
- No custom patterns
- Manual export process

### 2. Google HAR Sanitizer

[github.com/google/har-sanitizer](https://github.com/google/har-sanitizer)

**Pros:**

- Sanitizes passwords in form data
- CLI available
- Custom patterns supported

**Cons:**

- Data sent to cloud service (privacy concern)
- No correlation-preserving redaction
- No interactive review
- No capture integration

### 3. Cloudflare HAR Sanitizer

[Cloudflare Blog: Introducing HAR Sanitizer](https://blog.cloudflare.com/introducing-har-sanitizer-secure-har-sharing/)

**Pros:**

- Web-based (no installation)
- JWT smart redaction
- Data stays on device

**Cons:**

- No CLI/automation
- No custom patterns
- No correlation preservation
- No capture integration

### 4. Edgio HAR Tools

[github.com/Edgio/har-tools](https://github.com/Edgio/har-tools)

**Pros:**

- Sanitizes passwords in forms
- CLI available

**Cons:**

- No correlation-preserving redaction
- No interactive review
- Limited sanitization scope

## When to Use har-capture

Choose **har-capture** if you need:

- **Deep sanitization**: Beyond just cookies - IPs, MACs, emails, passwords, tokens
- **Correlation preservation**: Track same values across multiple requests
- **Automation**: CLI/Python API for batch processing
- **Custom patterns**: Extend sanitization for your specific use case
- **Local processing**: Data never leaves your machine
- **Capture + sanitize**: One-step workflow from browser to sanitized HAR

## When to Use Alternatives

**Use Chrome DevTools** if:

- Basic cookie/auth sanitization is sufficient
- You're already using DevTools
- No automation needed

**Use Cloudflare** if:

- You need JWT-specific redaction
- Web interface is preferred
- No custom patterns needed

**Use Google HAR Sanitizer** if:

- You're okay with cloud processing
- Basic form password sanitization is sufficient
