# Modules

Modules are the core scanning units.

## Structure

Each module:

- extends `ScanModule`
- defines:
  - name
  - stage
  - dependencies
  - required_context_keys
- implements async `run()`

---

## Example

```python
class ExampleModule(ScanModule):
    name = "example"
    stage = "WEB"

    async def run(self, target, context):
        ...
