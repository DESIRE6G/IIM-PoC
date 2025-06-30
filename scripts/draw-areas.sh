set -e

source .venv/bin/activate

M1=5
M2=15
M3=45
M4=55
M5=85
M6=95

python3 pysrc/set-area.py a $M1 $M5 $M3 $M2
python3 pysrc/set-area.py b $M2 $M6 $M5 $M4
python3 pysrc/set-area.py c $M4 $M5 $M6 $M2
python3 pysrc/set-area.py d $M2 $M3 $M5 $M1

echo DONE
