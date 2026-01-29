# HAR Capture - Background Research

> **Note**: This document captures the research that led to creating har-capture.
> For usage information, see the [README](../README.md).

## References

### Specifications

- [HAR 1.2 Specification](http://www.softwareishard.com/blog/har-12-spec/)
- [Playwright HAR Recording](https://playwright.dev/docs/mock#recording-a-har-file)
- [Chrome DevTools HAR Export](https://developer.chrome.com/docs/devtools/network/reference/#export)
- [OWASP Data Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

### Alternative Tools Evaluated

| Project | Language | Type | Notes |
|---------|----------|------|-------|
| [Google har-sanitizer](https://github.com/google/har-sanitizer) | Python/JS | Web UI + REST API | No CLI, needs tests |
| [Cloudflare har-sanitizer](https://blog.cloudflare.com/introducing-har-sanitizer-secure-har-sharing/) | JS | Web UI | JWT-focused |
| [Edgio/har-tools](https://github.com/Edgio/har-tools) | JS | Web UI | Drag-drop interface |
| [AbregaInc/har-cleaner](https://github.com/AbregaInc/har-cleaner) | TypeScript | Library | Jira integration |
| [jfromaniello/har-sanitizer](https://github.com/jfromaniello/har-sanitizer) | JS | Library | Basic sanitization |

### Related Projects

| Project | Purpose |
|---------|---------|
| [GSMA TSG Diagnostic Interface](https://github.com/GSMATerminals/TSG-IoT-devices-Standard-Diagnostic-Interface-Public) | Modem logging for Cat-M1/NB-IoT |
| [NYU IoT Inspector](https://github.com/nyu-mlab/iot-inspector-client) | Smart home traffic analysis |
| [IoTShark](https://github.com/sahilmgandhi/IotShark) | IoT traffic monitoring |
