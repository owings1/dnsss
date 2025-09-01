"""
AR-1 Autoregression time series algorithm

Reference:

- S. Deb, A. Srinivasan and S. Kuppili Pavan, "An improved DNS server selection algorithm for faster lookups,"
  2008 3rd International Conference on Communication Systems Software and Middleware and Workshops
  (COMSWARE '08), Bangalore, India, 2008, pp. 288-295, doi: 10.1109/COMSWA.2008.4554428.
  https://ieeexplore.ieee.org/document/4554428
"""
from __future__ import annotations

from typing import Annotated, ClassVar

from ..models import *
from . import bind
from ..utils import dsorted

class Params(bind.Params):
    P_count_min: PositiveInt = 4
    'Minimum sample size before using AR prediction for a server'
    alpha_min: PositiveFloat = 0.1
    'Minimum value for AR volatility parameter (alpha)'
    alpha_max: PositiveFloat = 0.9
    'Maximum value for AR volatility parameter (alpha)'
    stale_max: PositiveInt = 100
    'Maximum number of queries before a slow server is tried again'
    drc_count_min: PositiveInt = 10
    'Minimum number of queries to a server before deviation reset counter is checked'
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
    configured by `P_count_min`.
    """
    alpha: NonNegativeFloat = 0.0
    """
    AR server volatility parameter. From the text: "The closer alpha is to 1,
    the less volatile are the server response times." (p. 4)
    """
    latest: NonNegativeFloat = 0.0
    "The latest observed response time for this server"
    mean_xy: NonNegativeFloat = 0.0
    "The mean of the product of the last two response times"
    mean_v2: NonNegativeFloat = 0.0
    "The mean of the square of the response time to this server"
    idle: NonNegativeInt = 0
    """
    The number of queries the resolver has made to other servers since this
    server was accessed. When this reaches `stale_max`, this server will be
    selected. This ensures that slow servers are contacted periodically.
    """
    drc: NonNegativeInt = 0
    'Deviation reset counter'

    model_config: ClassVar = ConfigDict(
        terse_exclude=['idle', 'mean_v2', 'mean_xy', 'delta_m2', 'variance'])

    def observe(self, value: NonNegativeFloat) -> None:
        super().observe(value)
        self.mean_v2 += (value**2 - self.mean_v2) / self.count
        if self.count > 1:
            self.mean_xy += (self.latest * value) / (self.count - 1)
            # Calculate alpha. Formula (5) from the text (p. 4) reads:
            """
                            E[X(q) * X(q - 1)] - E[X**2]
                alpha  =  ----------------------------          (5)
                                E[X**2] - E[X**2]
            """
            # This is clearly an error, as the denominator equals zero.
            # What follows is a best-guess interpretation, and a work
            # in progress.
            mean2 = self.mean**2
            self.alpha = (self.mean_xy - mean2) / (self.mean_v2 - mean2)
        self.latest = value

class Config(bind.Config):
    params: Params = Field(default_factory=Params)

class State(bind.State):
    AR: Annotated[
        dict[Server, ARStats],
        PlainSerializer(lambda x: dsorted(x, key=lambda x: x[1].P))] = Field(default_factory=dict)
    model_config: ClassVar = ConfigDict(terse_exclude=['SR'])

    def post_config_init(self, config: Config) -> None:
        super().post_config_init(config)
        self.AR = {Si: ARStats(P=Ri) for Si, Ri in self.SR.items()}

class Resolver(bind.Resolver):
    config: Config
    state: State = Field(default_factory=State)

    def adjust(self, S: Server, R: NonNegativeFloat) -> None:
        super().adjust(S, R)
        params = self.config.params
        for Si, ARi in self.state.AR.items():
            if Si == S:
                ARi.observe(R)
                ARi.idle = 0
                if ARi.count > 1:
                    # Normalize alpha
                    """
                    Note that [formula] (5) can lead to negative alpha if a server
                    is not accessed consecutively even once. In order to prevent
                    this, and in general, very small or very large alpha values,
                    we always ensure that alpha is between 0.1 and 0.9. (p. 4)
                    """
                    ARi.alpha = max(params.alpha_min, min(params.alpha_max, ARi.alpha))
                    # Deviation reset counter
                    """
                    > [I]f there is a significantly large deviation in the observed
                    > response times from the mean response times, then we restart
                    > the complete estimation. (p. 4)
                    """
                    if abs(R - ARi.mean) > ARi.stdev * params.drc_stdev_co:
                        ARi.drc += 1
                    else:
                        ARi.drc = 0
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
                        ARi.drc >= params.drc_consec and
                        # We also require a sample size large enough to consider
                        # our measured stdev stable (drc_count_min).
                        ARi.count >= params.drc_count_min):
                            self.state.AR[Si] = ARi = ARStats(P=params.o)
            else:
                ARi.idle += 1
            if ARi.count < params.P_count_min:
                # Our sample size is too small to make an AR prediction, so we
                # fall back to the BIND algorithm.
                ARi.P = self.state.SR[Si]
            else:
                # Compute the AR prediction. Formula (4) from the text (p. 4):
                """
                prediction(X(q)) = alpha**k * X(q - k) + (1 - alpha**k) * E[X]
                """
                atok = ARi.alpha ** (ARi.idle + 1)
                ARi.P = atok * ARi.latest + (1 - atok) * ARi.mean
            self.state.SR[Si] = ARi.P

    def select(self, q: Question) -> Server:
        stale = [
            Si for Si, ARi in self.state.AR.items()
            if ARi.idle >= self.config.params.stale_max]
        if stale:
            # If we have stale servers, choose the stalest.
            return max(stale, key=lambda Si: self.state.AR[Si].idle)
        # Otherwise, choose based on lowest predicted response time.
        return super().select(q)
