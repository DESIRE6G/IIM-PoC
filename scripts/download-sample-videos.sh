set -e

wget --recursive --no-parent http://gycsaba96.web.elte.hu/sample-videos/
mv gycsaba96.web.elte.hu/sample-videos sample-videos
rm -r gycsaba96.web.elte.hu
find sample-videos/ -type f ! -name *.mp4 -exec rm {} +