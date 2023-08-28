```
walking the PEB is my favourite pastime. this fork of Nim_DInvoke tries to confuse common anti-PEB walking measures, like sticking non-executable DLLs in PEB and catching violation exceptions. the order of the walk is reversed, and any non-executable libraries are freed.
```