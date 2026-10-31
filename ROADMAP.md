# Kredoxi roadmap

The MVP establishes explicit synthetic credential resolution, not general
transparent substitution or production secret storage.

Next milestone: independently executed consumer and broker with reviewed
OS-peer-authenticated IPC/enrollment on one selected platform. Define
application identity and same-user attacker assumptions before implementation.

Then: signed/versioned policy lifecycle, protected local telemetry, provider
timeouts/rotation, and a reviewed provider-neutral production adapter. Research
config-loader/proxy/interception support against real supported read paths.
Do not expand into cloud/Kubernetes merely to increase feature count.

Open maintainer decisions: license, initial supported OS, private-key enrollment,
distribution signing/provenance and operational support. No automated releases
or merges until those decisions and review gates are agreed.
