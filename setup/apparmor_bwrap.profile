# AppArmor profile for bubblewrap (bwrap) — hot-potato native sandbox.
# Required on Ubuntu 24.04+ where kernel.apparmor_restrict_unprivileged_userns=1
# by default blocks unprivileged user namespace creation.
#
# Install:
#   sudo cp setup/apparmor_bwrap.profile /etc/apparmor.d/bwrap
#   sudo apparmor_parser -r /etc/apparmor.d/bwrap
#
# This grants bwrap permission to create user namespaces only.
# The (unconfined) flag means bwrap's child processes are not confined
# by this profile — their isolation comes from the namespaces + seccomp
# that bwrap sets up, not from AppArmor.

abi <abi/4.0>,
include <tunables/global>

profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
