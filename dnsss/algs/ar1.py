"""
AR-1 Autoregression time series algorithm

Reference:

- S. Deb, A. Srinivasan and S. Kuppili Pavan, "An improved DNS server selection algorithm for faster lookups,"
  2008 3rd International Conference on Communication Systems Software and Middleware and Workshops
  (COMSWARE '08), Bangalore, India, 2008, pp. 288-295, doi: 10.1109/COMSWA.2008.4554428.
  https://ieeexplore.ieee.org/document/4554428
"""
from __future__ import annotations

import math
import random
from datetime import datetime, timedelta
from typing import Any

from ..models import *
from ..utils import addmean
from . import bind


class Params(bind.Params):
    p: PositiveInt = 4
    'Minimium sample size before using AR prediction for a server'
    m: PositiveInt = 100
    'Maximum number of queries before a slow server is tried again'
    rbot: PositiveInt = 100
    'Minimum number of queries to a server before deviation reset counter is checked'
    rage: NonNegativeFloat = 60.0
    'Minimum age in seconds of server data before deviation reset counter is checked'
    rcnt: PositiveInt = 10
    'Number of consecutive queries to a server with high deviation from mean to trigger reset'
    alpha_min: PositiveFloat = 0.1
    'Minumum value for AR volatility parameter (alpha)'
    alpha_max: PositiveFloat = 0.9
    'Maximum value for AR volatility parameter (alpha)'

class ARData(BaseModel):
    "AR values calculated and tracked for an individual server"
    P: RTime = 0.0
    """
    The predicted response time of the next query to this server. This will
    only start to be calculated once the sample size is large enough, as
    configured by `Params.p`.
    """
    mean: RTime = 0.0
    'The running mean response time for this server'
    count: NonNegativeInt = 0
    'The total number of queries sent to this server'
    kth: NonNegativeInt = 0
    rqx: RTime = 0.0
    rqy: RTime = 0.0
    mean_sq: NonNegativeFloat = 0.0
    mean_xy: NonNegativeFloat = 0.0
    s: float = 0.0
    std: float = 0.0
    dcnt: NonNegativeInt = 0
    """
    Deviation reset counter. When this reaches `Params.rcnt`, the data is reset.
    """
    birth: datetime|None = None
    """
    Time of first query. This is checked against `Params.rage` to prevent
    deviation resets happening too quickly.
    """
    alpha: NonNegativeFloat = 0.0
    """
    AR server volatility parameter. From the text (p. 4):
    
    > The closer alpha is to 1, the less volatile are the server response times.
    """

    def age(self) -> timedelta:
        if self.birth:
            return datetime.now() - self.birth
        return timedelta()
    
class Resolver(bind.Resolver):

    class Config(bind.Resolver.Config):
        params: Params = Field(default_factory=Params)
    config: Resolver.Config

    AR: dict[Server, ARData]

    def __init__(self, config: Any) -> None:
        super().__init__(config)
        self.AR = {S: ARData() for S in self.config.servers}

    def adjust(self, S: Server, R: RTime) -> None:
        super().adjust(S, R)
        params = self.config.params
        for Si, ARi in self.AR.items():
            if Si == S:
                om = ARi.mean
                if not ARi.birth:
                    ARi.birth = datetime.now()
                ARi.kth = self.count
                ARi.count += 1
                ARi.mean = addmean(R, ARi.mean, ARi.count)
                ARi.mean_sq = addmean(R**2, ARi.mean_sq, ARi.count)
                ARi.rqy, ARi.rqx = ARi.rqx, R
                if ARi.count > 1:
                    # Compute running standard devation.
                    ARi.s += (R - om) * (R - ARi.mean)
                    ARi.std = math.sqrt(ARi.s / (self.count - 1))
                    # Calculate alpha. Formula (5) from the text (p. 4) reads:
                    """
                                  E[X(q) * X(q - 1)] - E[X**2]
                        alpha  =  ----------------------------          (5)
                                       E[X**2] - E[X**2]
                    """
                    # This is clearly an error, as the denominator equals zero.
                    # What follows is a best-effort interpretation, and a work
                    # in progress.
                    ARi.mean_xy = addmean(ARi.rqx * ARi.rqy, ARi.mean_xy, ARi.count - 1)
                    alpha_raw = (ARi.mean_xy - ARi.mean**2) / (ARi.mean_sq - ARi.mean**2)
                    ARi.alpha = max(params.alpha_min, min(params.alpha_max, alpha_raw))
                    # ARi.alpha = 1 - ARi.alpha
                    """
                    > [I]f there is a significantly large deviation in the observed
                    > response times from the mean response times, then we restart
                    > the complete estimation.... [W]e define a deviation to be
                    > significantly large if it is more than twice the measured
                    > standard deviation. (p. 4)
                    """
                    # To consider R highly deviant, we require a sample size large
                    # enough to consider our measured standard deviation stable,
                    # defined by `Params.rbot`. Otherwise we will keep clearing
                    # the data prematurely.
                    if ARi.count >= params.rbot and abs(R - ARi.mean) > ARi.std * 2:
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
                        # Thus we track the number of _consecutive_ queries
                        # resulting in deviant response times (dcnt), and require
                        # a threshold to be reached, as defined by `Params.rcnt`.
                        ARi.dcnt += 1
                        if (
                            ARi.dcnt >= params.rcnt and
                            # Additionally we configure a minimum age of the
                            # dataset -- the age of deviance -- before it can be
                            # reset, as defined by `Params.rage`.
                            ARi.age().total_seconds() >= params.rage):
                            self.AR[Si] = ARi = ARData()
                    else:
                        ARi.dcnt = 0
            if ARi.count >= params.p:
                # We have good enough intial data for this server to graduate
                # from the BIND algorithm and start making predictions (P).
                k = self.count - ARi.kth + 1
                ARi.P = ARi.alpha**k * ARi.rqx + (1 - ARi.alpha**k) * ARi.mean

    def select(self) -> Server:
        lo = None
        stale = []
        for Si, ARi in self.AR.items():
            # If our sample size for this server is adequate, we will have
            # made a prediction (P) from the AR data. Otherwise, we use the
            # R value from the BIND algorithm for the initial queries.
            Ri = ARi.P or self.SR[Si]
            # Ensure that even bad servers are contacted periodically.
            if self.count - ARi.kth > self.config.params.m:
                stale.append(Si)
            elif lo is None or Ri < lo:
                lo = Ri
                bests = [Si]
            elif Ri == lo:
                bests.append(Si)
        # If we have stale servers, choose one of them. Otherwise, pick the
        # server with the lowest predicted response time.
        return random.choice(stale or bests)

    def state(self, *, terse: bool = False) -> dict[str, Any]:
        parent = super().state()
        exclude = []
        if terse:
            exclude += TERSE_EXCLUDES
            parent.pop('SR', None)
        return dict(
            AR={
                Si: ARi.model_dump(exclude=exclude)
                for Si, ARi in sorted(
                    self.AR.items(),
                    key=lambda x: x[1].P)},
            **parent)

    def load(self, state: dict[str, Any]) -> None:
        super().load(state)
        self.AR = {Si: ARData.model_validate(ARi) for Si, ARi in state['AR'].items()}

TERSE_EXCLUDES = ['kth', 'rqy', 'mean_sq', 'mean_xy', 's', 'birth']
