"""
BIND algorithm, as described in:

- S. Deb, A. Srinivasan and S. Kuppili Pavan, "An improved DNS server selection algorithm for faster lookups,"
  2008 3rd International Conference on Communication Systems Software and Middleware and Workshops
  (COMSWARE '08), Bangalore, India, 2008, pp. 288-295, doi: 10.1109/COMSWA.2008.4554428.
  https://ieeexplore.ieee.org/document/4554428
"""
from __future__ import annotations

from typing import Annotated

from ..models import *
from ..utils import dvsorted
from . import base


class Params(base.Params):
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

class State(base.State):
    SR: Annotated[
        dict[Server, NonNegativeFloat],
        PlainSerializer(dvsorted)] = Field(default_factory=dict)
    """
    Mapping of server to R value, which corresponds loosely to the expected
    response time of the next query to that server. In reality, though, the
    value of R becomes drastically less than mean response times for slower
    servers as it decreases by the fixed coefficient (g), until the server is
    eventually selected, and R increases.
    """
    params: Params = Field(default_factory=Params, exclude=True)
    model_config = ConfigDict(server_dict_fields=['SR', 'SM'])

    def add(self, server: Server) -> None:
        super().add(server)
        if server not in self.SR:
            self.SR[server] = 0.0

    def observe(self, server: Server, rtime: NonNegativeFloat, code: Rcode, servers: list[Server]) -> None:
        super().observe(server, rtime, code, servers)
        for Si in servers:
            Ri = self.SR[Si]
            if Si == server:
                # For the selected server, the new value is the weighted
                # average of the prior value (Ri) and the measured response
                # time (R).
                #
                # On the first query, the prior value (Ri) will be 0, so we
                # override (a) to 0, which will make the initial value of (R)
                # equal to the first observed value.
                a = Ri and self.params.a
                r = a * Ri + (1 - a) * rtime
            else:
                # For all other servers, the value is slightly decreased by
                # a fixed coefficient (g).
                r = self.params.g * Ri
            self.SR[Si] = r

    def rank(self, server: Server) -> float:
        'Rank based on least R value'
        return self.SR[server]

class Config(base.Config):
    params: Params = Field(default_factory=Params, frozen=True)

class Resolver(base.Resolver):
    config: Config = Field(default_factory=Config, frozen=True)
    state: State = Field(default_factory=State, frozen=True)
