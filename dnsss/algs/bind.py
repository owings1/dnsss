"""
BIND algorithm, as described in:

- S. Deb, A. Srinivasan and S. Kuppili Pavan, "An improved DNS server selection algorithm for faster lookups,"
  2008 3rd International Conference on Communication Systems Software and Middleware and Workshops
  (COMSWARE '08), Bangalore, India, 2008, pp. 288-295, doi: 10.1109/COMSWA.2008.4554428.
  https://ieeexplore.ieee.org/document/4554428
"""
from __future__ import annotations

import random
from typing import Any

from ..models import *
from ..utils import dvsorted
from . import base


class Params(BaseModel):
    a: PositiveFloat = Field(default=0.7, lt=1.0)
    """
    Selected server weighting of prior R value. The newly-observed response
    time is weighted as (1 - a). So with a value of a=0.7, the new R value
    for the server will be 30% of the observed response time plus 70% of
    the previous R value.
    """
    g: PositiveFloat = Field(default=0.98, lt=1.0)
    """
    Non-selected server discount coefficient. After each query to a server,
    the R value for all other servers is always decreased, thus ensuring
    their eventual selection.
    """
    o: RTime = 0.05
    """
    The initial value of R for all servers. This is somewhat arbitrary, and
    only affects startup, since R values eventually converge
    """

class Resolver(base.Resolver):

    class Config(base.Resolver.Config):
        params: Params = Field(default_factory=Params)
    config: Resolver.Config

    SR: dict[Server, RTime]
    """
    Mapping of server to R value, which corresponds loosely to the expected
    response time of the next query to that server. In reality, though, the
    value of R becomes drastically less than mean response times for slower
    servers as it decreases by the fixed coefficient (g), until the server is
    eventually selected, and R increases.
    """

    def __init__(self, config: Any) -> None:
        super().__init__(config)
        self.SR = dict.fromkeys(self.config.servers, self.config.params.o)

    def adjust(self, S: Server, R: RTime) -> None:
        super().adjust(S, R)
        a = self.config.params.a
        g = self.config.params.g
        for Si, Ri in self.SR.items():
            if Si == S:
                # For the selected server, the new value is the weighted
                # average of the prior value (Ri) and the measured response
                # time (R).
                r = a * Ri + (1 - a) * R
            else:
                # For all other servers, the value is slightly decreased by
                # a fixed coefficient (g).
                r = g * Ri
            self.SR[Si] = r

    def select(self) -> Server:
        # Select the server(s) with the least R value. If there is a tie, which
        # is always the case on startup, pick a random one.
        lo = None
        for Si, Ri in self.SR.items():
            if lo is None or Ri < lo:
                lo = Ri
                bests = [Si]
            elif Ri == lo:
                bests.append(Si)
        return random.choice(bests)

    def state(self, *, terse: bool = False) -> dict[str, Any]:
        return dict(SR=dvsorted(self.SR)) | super().state()

    def load(self, state: dict[str, Any]) -> None:
        super().load(state)
        self.SR = state['SR']
