"""
AR-1 Autoregression time series algorithm

Reference:

- S. Deb, A. Srinivasan and S. Kuppili Pavan, "An improved DNS server selection algorithm for faster lookups,"
  2008 3rd International Conference on Communication Systems Software and Middleware and Workshops
  (COMSWARE '08), Bangalore, India, 2008, pp. 288-295, doi: 10.1109/COMSWA.2008.4554428.
  https://ieeexplore.ieee.org/document/4554428
"""
from __future__ import annotations

from typing import Annotated, Any

from ..models import *
from ..utils import dvsorted
from . import bind


class Params(bind.Params):
    p_count_min: PositiveInt = 4
    'Minimum sample size before using AR prediction for a server'
    alpha_min: PositiveFloat = 0.1
    'Minimum value for AR volatility parameter (alpha)'
    alpha_max: PositiveFloat = 0.9
    'Maximum value for AR volatility parameter (alpha)'
    idle_max: PositiveInt = 100
    'Maximum idle count before a server is tried again'
    drc_count_min: PositiveInt = 50
    'Minimum sample size before deviation reset counter is checked'
    drc_consec: PositiveInt = 5
    'Number of consecutive queries to a server with high deviation from mean to trigger reset'
    drc_stdev_co: PositiveInt = 2
    """
    How many standard devations from the mean to consider as highly deviant.
    From the text: "[W]e define a deviation to be significantly large if it is
    more than twice the measured standard deviation." (p. 4)
    """

class ARStats(RunningVariance):
    "AR values calculated and tracked for an individual server"
    P: NonNegativeFloat = 0.0
    """
    The predicted response time of the next query to this server. This will
    only start to be calculated once the sample size is large enough, as
    configured by `p_count_min`.
    """
    alpha: NonNegativeFloat = 0.0
    """
    AR server volatility parameter. From the text: "The closer alpha is to 1,
    the less volatile are the server response times." (p. 4)
    """
    latest: NonNegativeFloat = 0.0
    "The latest observed response time for this server"
    mean_xy: NonNegativeFloat = 0.0
    "The mean of the product of the last observed response times for this server"
    mean_v2: NonNegativeFloat = 0.0
    "The mean of the square of the response time to this server"
    idle: NonNegativeInt = 0
    """
    The number of queries the resolver has made to other servers since this
    server was accessed. When this reaches `idle_max`, this server will be
    selected. This ensures that slow servers are contacted periodically.
    """
    drc: NonNegativeInt = 0
    'Deviation reset counter'
    params: Params = Field(default_factory=Params, exclude=True)
    model_config = ConfigDict(
        ordering_attribute='P',
        report_exclude=['mean_v2', 'mean_xy', 'delta_m2', 'variance'])

    def observe(self, rtime: NonNegativeFloat) -> None:
        params = self.params
        if self.count:
            # Deviation reset counter
            """
            > [I]f there is a significantly large deviation in the observed
            > response times from the mean response times, then we restart
            > the complete estimation. (p. 4)
            """
            if abs(rtime - self.mean) > self.stdev * params.drc_stdev_co:
                self.drc += 1
            else:
                self.drc = 0
            # We don't want to let just one or two deviant response
            # times make us start all over again. We mainly want to
            # avoid getting mired by old datasets and overgrown sample
            # sizes that are no longer maleable. Stated in the text:
            """
            > This is important as the DNS server could be running
            > for a long period of time over which the behavior of
            > a server can change completely. For example, a server's
            > response times at night-time can be very different
            > from its response times during the day-time. (p. 4)
            """
            if (
                # Thus we track the number of _consecutive_ queries
                # resulting in deviant response times (drc), and require
                # a threshold to be reached (drc_consec).
                self.drc >= params.drc_consec and
                # We also require a sample size large enough to consider
                # our measured stdev stable (drc_count_min).
                self.count >= params.drc_count_min):
                    self.reset()
        super().observe(rtime)
        self.mean_v2 += (rtime**2 - self.mean_v2) / self.count
        if self.count > 1:
            self.mean_xy += (self.latest * rtime) / (self.count - 1)
            # Calculate alpha. Formula (5) from the text (p. 4) reads:
            """
                            E[X(q) * X(q - 1)] - E[X**2]
                alpha  =  ----------------------------          (5)
                                E[X**2] - E[X**2]
            """
            # This is clearly an error, as the denominator equals zero.
            # Here, we interpret the denominator as:
            #
            #                   E[X**2] - E[X]**2
            #
            mean2 = self.mean**2
            self.alpha = (self.mean_xy - mean2) / (self.mean_v2 - mean2)
            # Normalize alpha
            """
            > Note that [formula] (5) can lead to negative alpha if a server
            > is not accessed consecutively even once. In order to prevent
            > this, and in general, very small or very large alpha values,
            > we always ensure that alpha is between 0.1 and 0.9. (p. 4)
            """
            self.alpha = max(params.alpha_min, min(params.alpha_max, self.alpha))
        self.latest = rtime
        # Clear the idle count
        self.idle = 0

    def predict(self) -> None:
        # Compute the AR prediction. Formula (4) from the text (p. 4):
        """
        prediction(X(q)) = alpha**k * X(q - k) + (1 - alpha**k) * E[X]
        """
        atok = self.alpha ** (self.idle + 1)
        self.P = atok * self.latest + (1 - atok) * self.mean

    def reset(self) -> None:
        "Reset the stats"
        defaults = type(self)(params=self.params).model_dump()
        for name, value in defaults.items():
            setattr(self, name, value)
        self.alpha = self.params.alpha_min

class State(bind.State):
    SAR: Annotated[
        dict[Server, ARStats],
        PlainSerializer(dvsorted)] = Field(default_factory=dict)
    "Mapping of each server to its ARStats"
    params: Params = Field(default_factory=Params, exclude=True)
    model_config = ConfigDict(server_dict_fields=['SAR', 'SM', 'SR'])

    def add(self, server: Server) -> None:
        super().add(server)
        if server in self.SAR:
            self.SAR[server].params = self.params
        else:
            self.SAR[server] = ARStats(params=self.params)
            self.SAR[server].reset()

    def observe(self, server: Server, rtime: NonNegativeFloat, code: Rcode, servers: list[Server]) -> None:
        with self._lock:
            super().observe(server, rtime, code, servers)
            for Si in servers:
                ARi = self.SAR[Si]
                if Si == server:
                    # Update the ARStats of the queried server
                    ARi.observe(rtime)
                else:
                    # Increment the idle count for all the other servers
                    ARi.idle += 1
                if ARi.count >= self.params.p_count_min:
                    # Compute the AR prediction for every server
                    ARi.predict()

    def rank(self, server: Server) -> float:
        AR = self.SAR[server]
        return (
            # For idle servers, rank idlest first.
            AR.idle > self.params.idle_max and -float(AR.idle) or
            # Rank based on AR prediction if available.
            AR.P or
            # Fall back to BIND algorithm.
            super().rank(server))

    def load(self, data: Any) -> None:
        super().load(data)
        for ARi in self.SAR.values():
            ARi.params = self.params

class Config(bind.Config):
    params: Params = Field(default_factory=Params, frozen=True)

class Resolver(bind.Resolver):
    config: Config = Field(default_factory=Config, frozen=True)
    state: State = Field(default_factory=State, frozen=True)
