package trust_engine

import (
    md "github.com/vs-uulm/ztsfc_http_pdp/internal/app/metadata"
    logger "github.com/vs-uulm/ztsfc_http_logger"
    rattr "github.com/vs-uulm/ztsfc_http_attributes"
    //"github.com/vs-uulm/ztsfc_http_pdp/internal/app/policies"
)

type Opinion struct {
    b float32
    d float32
    u float32
    a float32
    weight float32
}

var (
    // User
    PWAuthenticated = Opinion{1,0,0,0.5,10}
    UsualTime = Opinion{1,0,0,0.5,5}
    UsualService = Opinion{1,0,0,0.5,5}

    // Device
    CertAuthenticated = Opinion{1,0,0,0.5,15}
    FromTrustedLocation = Opinion{1,0,0,0.5,5}
    WithinAllowedRequestRate = Opinion{1,0,0,0.5,10}
)

func CalcTrustScoreSL(sysLogger *logger.Logger, cpm *md.Cp_metadata, user *rattr.User, device *rattr.Device) {
    userTrustOpinion := calcUserTrustSL(sysLogger, cpm, user)

    deviceTrustOpinion := calcDeviceTrustSL(sysLogger, cpm)

    totalTrustOpinion := weightedCumulativeFusion(userTrustOpinion, deviceTrustOpinion)

    sysLogger.Debugf("trust_engine: CalcUserTrustSL(): b=%f, d=%f, u=%f, a=%f, totalTrustOpinioneight=%f", totalTrustOpinion.b, totalTrustOpinion.d, totalTrustOpinion.u, totalTrustOpinion.a, totalTrustOpinion.weight)
}

func calcUserTrustSL(sysLogger *logger.Logger, cpm *md.Cp_metadata, user *rattr.User) (userTrustOpinion Opinion) {
    // Fuse PWAuthenticated and UsualTime
    userTrustOpinion = Opinion{}
    wAB := weightedCumulativeFusion(PWAuthenticated, UsualTime)
    wAB = weightedCumulativeFusion(wAB, UsualService)
    return
}

func calcDeviceTrustSL(sysLogger *logger.Logger, cpm *md.Cp_metadata) (deviceTrustOpinion Opinion) {
    deviceTrustOpinion = Opinion{}
    wAB := weightedCumulativeFusion(CertAuthenticated, FromTrustedLocation)
    wAB = weightedCumulativeFusion(wAB, WithinAllowedRequestRate)
    return
}

func weightedCumulativeFusion(wA, wB Opinion)  (wAB Opinion) {
    wAB = Opinion{}
    k := wA.u + wB.u - wA.u * wB.u
    wAB.b = ((k - wA.u * wB.u) * (wA.weight * wA.b * wB.u + wB.weight * wB.b * wA.u)) / (k * (wA.weight * wB.u + wB.weight * wA.u - (wA.weight + wB.weight) * wA.u * wB.u))
    wAB.d = ((k - wA.u * wB.u) * (wA.weight * wA.d * wB.u + wB.weight * wB.d * wA.u)) / (k * (wA.weight * wB.u + wB.weight * wA.u - (wA.weight + wB.weight) * wA.u * wB.u))
    wAB.u = (wA.u * wB.u) / k
    wAB.a = (wA.weight * wA.a * wB.u + wB.weight * wB.a * wA.u - (wA.weight * wA.a + wB.weight * wB.a) * wA.u * wB.u) / ((wA.weight * wB.u + wB.weight * wA.u - (wA.weight + wB.weight)* wA.u * wB.u))
    wAB.weight = (wA.weight * (wB.u - wB.u * wA.u) + wB.weight * (wA.u - wB.u * wA.u)) / (wA.u + wB.u - 2.0 * wB.u * wA.u)
    return wAB
}
