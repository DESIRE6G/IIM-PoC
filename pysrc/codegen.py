
from p4rrot.generator_tools import *
from p4rrot.known_types import *  
from p4rrot.standard_fields import *
from p4rrot.core.commands import *  

from plugins import *

M1=5
M2=15
M3=45
M4=55
M5=85
M6=95

area1 = (M1, M5, M3, M2)
area2 = (M2, M6, M5, M4)
area3 = (M4, M5, M6, M2)
area4 = (M2, M3, M5, M1)
areas = [area1, area2, area3, area4]

UID.reset()
fp = FlowProcessor(
        istruct = [('coord_x',uint32_t),('coord_y',uint32_t)]
        )

for i,(ax,ay,bx,by) in enumerate(areas):
    (
    fp
    .add(IfExpr(f'{min(ax,bx)} <= coord_x && coord_x <={max(ax,bx)} && {min(ay,by)} <= coord_y && coord_y <={max(ay,by)}'))
            .add(ConfigureFeed(i+1,FilteringMode.NONE))
        .Else()
            .add(ConfigureFeed(i+1,FilteringMode.EVERY))
        .EndIf()
    )  


fs = FlowSelector(
        'IPV4_UDP',
        [(UdpDstPort,5555)],
        fp
    )

solution = Solution()
solution.add_flow_processor(fp)
solution.add_flow_selector(fs)
solution.get_generated_code().dump('tmp')