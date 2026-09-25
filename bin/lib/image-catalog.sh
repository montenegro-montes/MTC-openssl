# Shared preparation/installation stages. Preserve existing stage numbers 1..3.
IMAGES=(mt-tls-lab:local mt-tls-mtc:local mt-tls-capture:local mt-tls-mtc-profile:local mt-tls-mtc-mutual:local mt-tls-network-measurement:local mt-tls-network:local)
FILES=(docker/base/Dockerfile docker/base/Dockerfile.mtc docker/base/Dockerfile.capture docker/validation/Dockerfile.profile campaigns/scaling/mutual_authentication_crossover/Dockerfile.mutual_metrics docker/network/Dockerfile.measurement docker/network/Dockerfile.network)
# Zero-based parent indices: capture and profiling are siblings under MTC.
PARENTS=(-1 0 1 1 3 3 5)
