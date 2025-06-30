
# USAGE:
# $1:  max bytes/s
#

set -e

sudo ./nikss/build/nikss-ctl meter update pipe 5 ingress_bottleneck_m index 0 $1:$1 5000:5000
