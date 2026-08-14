# meta

One value per file, one line per file, no comments. Every file here is inlined
verbatim into the deliverable by a `#__inc:` placeholder, so anything written
next to the value would be shipped with it — which is why the explanations live
in this file instead.

| File | Variable |
|---|---|
| `Version.ps1` | `$Version` |
| `Author.ps1` | `$Author` |
| `ProjectUrl.ps1` | `$ProjectUrl` |
| `AppName.ps1` | `$AppName` |

`$Version` is the single source of truth for the version number. An updater
compares one number against one release, so a version kept in the template as
well would be a second number waiting to drift apart. `tools\dist.ps1` reads this
file to name the release archive, and a release workflow can read it the same
way: one line, one quoted value.

Bumping the version is editing `Version.ps1` and nothing else.

`$AppName` is the product name, and it is what everything outside the process is
found by: the registry key, the instance directory under `%LOCALAPPDATA%`, the
window titles and the name the autostart entry carries. It sits here rather than
in the template for the same reason `$Version` does -- a name written in two
places is a name that will differ in one of them.
