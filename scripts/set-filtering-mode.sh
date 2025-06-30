
# USAGE:
# $1:  camera id
# $2: id for filering mode
#

set -e

sudo ./nikss/build/nikss-ctl register set pipe 5 ingress_filtering_mode index $1 value $2
