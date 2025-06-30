
from typing import Optional
from p4rrot.generator_tools import *


class FilteringMode:
    NONE = 0
    EVERY = 1
    HALF = 2

class ConfigureFeed(Command):

    def __init__(self,camer_id: int,filtering_mode: int,env:Optional[Environment] = None):
        super().__init__()
        self.camera_id = camer_id
        self.filtering_mode = filtering_mode
        self.env = env

        if self.env!=None:
            self.check()

    def check(self):
        pass

    def get_generated_code(self):
        gc = GeneratedCode()
        gc.get_apply().writeln(f"set_filtering_mode({self.camera_id},{self.filtering_mode});")
        return gc