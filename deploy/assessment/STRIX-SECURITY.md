# Strix container dependency security overlay

The image retains unmodified Strix source `1.7.0`, commit
`55bc07991aacb1c26a81b43e7ca53148730d2019`, its license and its upstream lock.
Deckard applies an explicit downstream dependency overlay after the frozen install.
The resulting environment is not the unchanged upstream lock environment.

| Package | Upstream lock | Downstream security version |
| --- | --- | --- |
| PyJWT | 2.13.0 | 2.14.0 |
| anyio | 4.14.1 | 4.14.2 |
| aiohttp | 3.14.3 | [3.14.4](https://pypi.org/project/aiohttp/3.14.4/) |
| certifi | 2026.6.17 | [2026.10.19](https://pypi.org/project/certifi/2026.10.19/) |
| cryptography | 48.0.1 | 50.0.0 |
| filelock | 3.29.4 | [4.2.1](https://pypi.org/project/filelock/4.2.1/) |
| graphql-core | 3.2.11 | [3.2.12](https://pypi.org/project/graphql-core/3.2.12/) |
| Pillow | 12.3.0 | [13.0.0](https://pypi.org/project/pillow/13.0.0/) |
| pypdf | 6.14.2 | [6.21.2](https://pypi.org/project/pypdf/6.21.2/) |
| urllib3 | 2.7.0 | 2.8.0 |
| yarl | 1.24.2 | [1.25.1](https://pypi.org/project/yarl/1.25.1/) |

These versions address fixable HIGH/CRITICAL findings in the original container.
The image installs only the exact packages and SHA256-verified official PyPI wheels
listed in `strix-security-requirements.txt`. It disables dependency resolution and
source builds for this overlay, then runs `uv pip check` on the installed environment.
The requirements cover Linux Python `3.13` on `amd64` and `arm64` only.
The native aiohttp, Pillow and yarl wheel hashes cover both architectures. Other new
overlay wheels are platform-independent. Tests pin the official release hashes
and exercise image/PDF round trips alongside the real SDK/session contracts.
The yarl update satisfies aiohttp `3.14.4`'s declared `yarl>=1.25.1` requirement.

Upstream caps `cryptography<49` because newer releases lack the Intel macOS
universal2 wheel. This Linux-only image deliberately overrides that packaging cap.
It does not modify or claim compatibility for upstream Intel macOS releases.
The genuine Agents SDK remains `0.19.0`; no engine, SDK or tool dependencies are removed.

The final image excludes the base image's unused system `pip` package and its
`ensurepip` bootstrap wheel. Both bundled vulnerable `msgpack 1.1.2`,
`setuptools 70.3.0` and `urllib3 2.7.0`. These are installer-only copies, not
Strix virtual-environment dependencies. The final image cannot install packages
with system pip or bootstrap it from the removed wheel. Dependency installation
and validation happen in the build stage with pinned `uv`.

Run the real SDK/session and local protocol regression tests against the rebuilt
container. Run `test_strix_security.py` with `STRIX_SECURITY_CHECK=1` there too.
A fresh vulnerability scan must pass before publishing. These tests do not prove
a live-model assessment, exploit validity or Kubernetes network containment.
