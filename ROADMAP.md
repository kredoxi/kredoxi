# Kredoxi roadmap

The MVP establishes explicit synthetic credential resolution, not general
transparent substitution or production secret storage.

Process separation is now demonstrated with independent broker, consumer and
synthetic-service commands over the existing loopback mTLS protocol. This does
not enforce distinct OS users, attest executable identity, or make the stdin
bootstrap a production enrollment channel.

Next milestone: propose and review an Architecture ADR comparing OS-native
peer-authenticated IPC/enrollment with the existing mTLS boundary. Obtain owner
approval before choosing an OS identity mechanism. Define application identity
and same-user attacker assumptions before implementation.

Then: signed/versioned policy lifecycle, protected local telemetry, provider
timeouts/rotation, and a reviewed provider-neutral production adapter. Research
config-loader/proxy/interception support against real supported read paths.
Do not expand into cloud/Kubernetes merely to increase feature count.

Open maintainer decisions: license, initial supported OS, private-key enrollment,
distribution signing/provenance and operational support. No automated releases
or merges until those decisions and review gates are agreed.
