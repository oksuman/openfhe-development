/**
 * @brief Implementation of DECOMP key switching
 */
#define PROFILE

#include "keyswitch/keyswitch-decomp.h"

#include "key/privatekey.h"
#include "key/publickey.h"
#include "key/evalkeyrelin.h"
#include "schemerns/rns-cryptoparameters.h"
#include "cryptocontext.h"
#include <iostream>

namespace lbcrypto {

EvalKey<DCRTPoly> KeySwitchDECOMP::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                        const PrivateKey<DCRTPoly> newKey) const {
    std::cout << "Using KeySwitchDECOMP::KeySwitchGenInternal (2 keys)" << std::endl;
    
    EvalKeyRelin<DCRTPoly> ek(std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext()));

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(newKey->GetCryptoParameters());

    const std::shared_ptr<ParmType> paramsQ  = cryptoParams->GetElementParams();
    const std::shared_ptr<ParmType> paramsQP = cryptoParams->GetParamsQP();

    size_t sizeQ  = paramsQ->GetParams().size();
    size_t sizeQP = paramsQP->GetParams().size();

    DCRTPoly sOld = oldKey->GetPrivateElement();
    DCRTPoly sNew = newKey->GetPrivateElement().Clone();

    // skNew is currently in basis Q. This extends it to basis QP.
    sNew.SetFormat(Format::COEFFICIENT);

    DCRTPoly sNewExt(paramsQP, Format::COEFFICIENT, true);

    // The part with basis Q
    for (size_t i = 0; i < sizeQ; i++) {
        sNewExt.SetElementAtIndex(i, sNew.GetElementAtIndex(i));
    }

    // The part with basis P
    for (size_t j = sizeQ; j < sizeQP; j++) {
        const NativeInteger& pj    = paramsQP->GetParams()[j]->GetModulus();
        const NativeInteger& rootj = paramsQP->GetParams()[j]->GetRootOfUnity();
        auto sNew0                 = sNew.GetElementAtIndex(0);
        sNew0.SwitchModulus(pj, rootj, 0, 0);
        sNewExt.SetElementAtIndex(j, std::move(sNew0));
    }

    sNewExt.SetFormat(Format::EVALUATION);

    const auto ns      = cryptoParams->GetNoiseScale();
    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DugType dug;

    size_t numPartQ = cryptoParams->GetNumPartQ();

    std::vector<DCRTPoly> av(numPartQ);
    std::vector<DCRTPoly> bv(numPartQ);

    std::vector<NativeInteger> PModq = cryptoParams->GetPModq();
    size_t numPerPartQ               = cryptoParams->GetNumPerPartQ();

    for (size_t part = 0; part < numPartQ; ++part) {
        DCRTPoly a(dug, paramsQP, Format::EVALUATION);
        DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
        DCRTPoly b(paramsQP, Format::EVALUATION, true);

        // starting and ending position of current part
        size_t startPartIdx = numPerPartQ * part;
        size_t endPartIdx   = (sizeQ > (startPartIdx + numPerPartQ)) ? (startPartIdx + numPerPartQ) : sizeQ;

        for (size_t i = 0; i < sizeQP; ++i) {
            auto ai    = a.GetElementAtIndex(i);
            auto ei    = e.GetElementAtIndex(i);
            auto sNewi = sNewExt.GetElementAtIndex(i);

            if (i < startPartIdx || i >= endPartIdx) {
                b.SetElementAtIndex(i, -ai * sNewi + ns * ei);
            }
            else {
                // P * sOld is only applied for the current part
                auto sOldi = sOld.GetElementAtIndex(i);
                b.SetElementAtIndex(i, -ai * sNewi + PModq[i] * sOldi + ns * ei);
            }
        }

        av[part] = a;
        bv[part] = b;
    }

    ek->SetAVector(std::move(av));
    ek->SetBVector(std::move(bv));
    ek->SetKeyTag(newKey->GetKeyTag());
    return ek;
}

EvalKey<DCRTPoly> KeySwitchDECOMP::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                        const PrivateKey<DCRTPoly> newKey,
                                                        const EvalKey<DCRTPoly> ekPrev) const {
    std::cout << "Using KeySwitchDECOMP::KeySwitchGenInternal (3 params)" << std::endl;
    
    EvalKeyRelin<DCRTPoly> ek(std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext()));

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(newKey->GetCryptoParameters());

    const std::shared_ptr<ParmType> paramsQ  = cryptoParams->GetElementParams();
    const std::shared_ptr<ParmType> paramsQP = cryptoParams->GetParamsQP();

    usint sizeQ  = paramsQ->GetParams().size();
    usint sizeQP = paramsQP->GetParams().size();

    DCRTPoly sOld = oldKey->GetPrivateElement();

    DCRTPoly newp0 = newKey->GetPrivateElement().Clone();
    newp0.SetFormat(Format::COEFFICIENT);

    DCRTPoly sNewExt(paramsQP, Format::COEFFICIENT, true);

    // The part with basis Q
    for (size_t i = 0; i < sizeQ; i++) {
        sNewExt.SetElementAtIndex(i, newp0.GetElementAtIndex(i));
    }

    // The part with basis P
    for (size_t j = sizeQ; j < sizeQP; j++) {
        const NativeInteger& pj    = paramsQP->GetParams()[j]->GetModulus();
        const NativeInteger& rootj = paramsQP->GetParams()[j]->GetRootOfUnity();
        auto sNew0                 = newp0.GetElementAtIndex(0);
        sNew0.SwitchModulus(pj, rootj, 0, 0);
        sNewExt.SetElementAtIndex(j, std::move(sNew0));
    }

    sNewExt.SetFormat(Format::EVALUATION);

    const auto ns      = cryptoParams->GetNoiseScale();
    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DugType dug;

    auto numPartQ = cryptoParams->GetNumPartQ();

    std::vector<DCRTPoly> av(numPartQ);
    std::vector<DCRTPoly> bv(numPartQ);

    std::vector<NativeInteger> PModq = cryptoParams->GetPModq();
    usint numPerPartQ                = cryptoParams->GetNumPerPartQ();

    for (usint part = 0; part < numPartQ; part++) {
        DCRTPoly a = (ekPrev == nullptr) ? DCRTPoly(dug, paramsQP, Format::EVALUATION) :  // single-key HE
                                           ekPrev->GetAVector()[part];                     // threshold HE
        DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
        DCRTPoly b(paramsQP, Format::EVALUATION, true);

        // starting and ending position of current part
        usint startPartIdx = numPerPartQ * part;
        usint endPartIdx   = (sizeQ > startPartIdx + numPerPartQ) ? (startPartIdx + numPerPartQ) : sizeQ;

        for (usint i = 0; i < sizeQP; i++) {
            auto e0i = e.GetElementAtIndex(i);
            auto ai = a.GetElementAtIndex(i);
            auto sNewi = sNewExt.GetElementAtIndex(i);

            if (i < startPartIdx || i >= endPartIdx) {
                b.SetElementAtIndex(i, -ai * sNewi + ns * e0i);
            }
            else {
                // P * sOld is only applied for the current part
                auto sOldi = sOld.GetElementAtIndex(i);
                b.SetElementAtIndex(i, -ai * sNewi + PModq[i] * sOldi + ns * e0i);
            }
        }

        av[part] = std::move(a);
        bv[part] = std::move(b);
    }

    ek->SetAVector(std::move(av));
    ek->SetBVector(std::move(bv));
    ek->SetKeyTag(newKey->GetKeyTag());

    return ek;
}

EvalKey<DCRTPoly> KeySwitchDECOMP::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                        const PublicKey<DCRTPoly> newKey) const {
    std::cout << "Using KeySwitchDECOMP::KeySwitchGenInternal (oldKey, newPubKey)" << std::endl;
    
    EvalKeyRelin<DCRTPoly> ek = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext());

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(newKey->GetCryptoParameters());

    const std::shared_ptr<ParmType> paramsQ  = cryptoParams->GetElementParams();
    const std::shared_ptr<ParmType> paramsQP = cryptoParams->GetParamsQP();

    usint sizeQ  = paramsQ->GetParams().size();
    usint sizeQP = paramsQP->GetParams().size();

    DCRTPoly sOld = oldKey->GetPrivateElement();

    DCRTPoly newp0 = newKey->GetPublicElements().at(0);
    DCRTPoly newp1 = newKey->GetPublicElements().at(1);

    const auto ns      = cryptoParams->GetNoiseScale();
    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    TugType tug;

    auto numPartQ = cryptoParams->GetNumPartQ();

    std::vector<DCRTPoly> av(numPartQ);
    std::vector<DCRTPoly> bv(numPartQ);

    std::vector<NativeInteger> PModq = cryptoParams->GetPModq();
    usint numPerPartQ                = cryptoParams->GetNumPerPartQ();

    for (usint part = 0; part < numPartQ; part++) {
        DCRTPoly u = (cryptoParams->GetSecretKeyDist() == GAUSSIAN) ? DCRTPoly(dgg, paramsQP, Format::EVALUATION) :
                                                                      DCRTPoly(tug, paramsQP, Format::EVALUATION);

        DCRTPoly e0(dgg, paramsQP, Format::EVALUATION);
        DCRTPoly e1(dgg, paramsQP, Format::EVALUATION);

        DCRTPoly a(paramsQP, Format::EVALUATION, true);
        DCRTPoly b(paramsQP, Format::EVALUATION, true);

        // starting and ending position of current part
        usint startPartIdx = numPerPartQ * part;
        usint endPartIdx   = (sizeQ > startPartIdx + numPerPartQ) ? (startPartIdx + numPerPartQ) : sizeQ;

        for (usint i = 0; i < sizeQP; i++) {
            auto e0i = e0.GetElementAtIndex(i);
            auto e1i = e1.GetElementAtIndex(i);

            auto ui = u.GetElementAtIndex(i);

            auto newp0i = newp0.GetElementAtIndex(i);
            auto newp1i = newp1.GetElementAtIndex(i);

            a.SetElementAtIndex(i, newp1i * ui + ns * e1i);

            if (i < startPartIdx || i >= endPartIdx) {
                b.SetElementAtIndex(i, newp0i * ui + ns * e0i);
            }
            else {
                // P * sOld is only applied for the current part
                auto sOldi = sOld.GetElementAtIndex(i);
                b.SetElementAtIndex(i, newp0i * ui + ns * e0i + PModq[i] * sOldi);
            }
        }

        av[part] = a;
        bv[part] = b;
    }

    ek->SetAVector(std::move(av));
    ek->SetBVector(std::move(bv));
    ek->SetKeyTag(newKey->GetKeyTag());

    return ek;
}

void KeySwitchDECOMP::KeySwitchInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> ek) const {
    std::cout << "Using KeySwitchDECOMP::KeySwitchInPlace" << std::endl;
    
    std::vector<DCRTPoly>& cv = ciphertext->GetElements();

    std::shared_ptr<std::vector<DCRTPoly>> ba = (cv.size() == 2) ? KeySwitchCore(cv[1], ek) : KeySwitchCore(cv[2], ek);

    cv[0].SetFormat((*ba)[0].GetFormat());
    cv[0] += (*ba)[0];

    cv[1].SetFormat((*ba)[1].GetFormat());
    if (cv.size() > 2) {
        cv[1] += (*ba)[1];
    }
    else {
        cv[1] = (*ba)[1];
    }
    cv.resize(2);
}

Ciphertext<DCRTPoly> KeySwitchDECOMP::KeySwitchExt(ConstCiphertext<DCRTPoly> ciphertext, bool addFirst) const {
    std::cout << "Using KeySwitchDECOMP::KeySwitchExt" << std::endl;
    
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();

    const auto paramsQl  = cv[0].GetParams();
    const auto paramsP   = cryptoParams->GetParamsP();
    const auto paramsQlP = cv[0].GetExtendedCRTBasis(paramsP);

    size_t sizeQl = paramsQl->GetParams().size();
    usint sizeCv  = cv.size();
    std::vector<DCRTPoly> resultElements(sizeCv);
    for (usint k = 0; k < sizeCv; k++) {
        resultElements[k] = DCRTPoly(paramsQlP, Format::EVALUATION, true);
        if ((addFirst) || (k > 0)) {
            auto cMult = cv[k].TimesNoCheck(cryptoParams->GetPModq());
            for (usint i = 0; i < sizeQl; i++) {
                resultElements[k].SetElementAtIndex(i, std::move(cMult.GetElementAtIndex(i)));
            }
        }
    }

    Ciphertext<DCRTPoly> result = ciphertext->CloneZero();
    result->SetElements(std::move(resultElements));
    return result;
}

Ciphertext<DCRTPoly> KeySwitchDECOMP::KeySwitchDown(ConstCiphertext<DCRTPoly> ciphertext) const {
    std::cout << "Using KeySwitchDECOMP::KeySwitchDown" << std::endl;
    
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    const auto paramsP   = cryptoParams->GetParamsP();
    const auto paramsQlP = ciphertext->GetElements()[0].GetParams();

    // TODO : (Andrey) precompute paramsQl in cryptoparameters
    usint sizeQl = paramsQlP->GetParams().size() - paramsP->GetParams().size();
    std::vector<NativeInteger> moduliQ(sizeQl);
    std::vector<NativeInteger> rootsQ(sizeQl);
    for (size_t i = 0; i < sizeQl; i++) {
        moduliQ[i] = paramsQlP->GetParams()[i]->GetModulus();
        rootsQ[i]  = paramsQlP->GetParams()[i]->GetRootOfUnity();
    }
    auto paramsQl = std::make_shared<typename DCRTPoly::Params>(2 * paramsQlP->GetRingDimension(), moduliQ, rootsQ);

    auto cTilda = ciphertext->GetElements();

    PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    DCRTPoly ct0 = cTilda[0].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                           cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                           cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                           cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                           cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

    DCRTPoly ct1 = cTilda[1].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                           cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                           cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                           cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                           cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

    Ciphertext<DCRTPoly> result = ciphertext->CloneZero();
    result->SetElements(std::vector<DCRTPoly>{std::move(ct0), std::move(ct1)});
    return result;
}

DCRTPoly KeySwitchDECOMP::KeySwitchDownFirstElement(ConstCiphertext<DCRTPoly> ciphertext) const {
    std::cout << "Using KeySwitchDECOMP::KeySwitchDownFirstElement" << std::endl;
    
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    const std::vector<DCRTPoly>& cTilda = ciphertext->GetElements();

    const auto paramsP   = cryptoParams->GetParamsP();
    const auto paramsQlP = cTilda[0].GetParams();

    usint sizeQl = paramsQlP->GetParams().size() - paramsP->GetParams().size();
    std::vector<NativeInteger> moduliQ(sizeQl);
    std::vector<NativeInteger> rootsQ(sizeQl);
    for (size_t i = 0; i < sizeQl; i++) {
        moduliQ[i] = paramsQlP->GetParams()[i]->GetModulus();
        rootsQ[i]  = paramsQlP->GetParams()[i]->GetRootOfUnity();
    }
    auto paramsQl = std::make_shared<typename DCRTPoly::Params>(2 * paramsQlP->GetRingDimension(), moduliQ, rootsQ);

    PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    DCRTPoly cv0 = cTilda[0].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                           cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                           cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                           cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                           cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

    return cv0;
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchDECOMP::KeySwitchCore(const DCRTPoly& a,
                                                                      const EvalKey<DCRTPoly> evalKey) const {
    std::cout << "Using KeySwitchDECOMP::KeySwitchCore" << std::endl;
    
    return EvalFastKeySwitchCore(EvalKeySwitchPrecomputeCore(a, evalKey->GetCryptoParameters()), evalKey,
                                 a.GetParams());
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchDECOMP::EvalKeySwitchPrecomputeCore(
    const DCRTPoly& c, std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParamsBase) const {
    std::cout << "Using KeySwitchDECOMP::EvalKeySwitchPrecomputeCore" << std::endl;
    
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoParamsBase);

    const std::shared_ptr<ParmType> paramsQl  = c.GetParams();
    const std::shared_ptr<ParmType> paramsP   = cryptoParams->GetParamsP();
    const std::shared_ptr<ParmType> paramsQlP = c.GetExtendedCRTBasis(paramsP);

    size_t sizeQl  = paramsQl->GetParams().size();
    size_t sizeP   = paramsP->GetParams().size();
    size_t sizeQlP = sizeQl + sizeP;

    uint32_t alpha = cryptoParams->GetNumPerPartQ();
    // The number of digits of the current ciphertext
    uint32_t numPartQl = ceil((static_cast<double>(sizeQl)) / alpha);
    if (numPartQl > cryptoParams->GetNumberOfQPartitions())
        numPartQl = cryptoParams->GetNumberOfQPartitions();

    std::vector<DCRTPoly> partsCt(numPartQl);

    // Digit decomposition
    // Zero-padding and split
    for (uint32_t part = 0; part < numPartQl; part++) {
        if (part == numPartQl - 1) {
            auto paramsPartQ = cryptoParams->GetParamsPartQ(part);

            uint32_t sizePartQl = sizeQl - alpha * part;

            std::vector<NativeInteger> moduli(sizePartQl);
            std::vector<NativeInteger> roots(sizePartQl);

            for (uint32_t i = 0; i < sizePartQl; i++) {
                moduli[i] = paramsPartQ->GetParams()[i]->GetModulus();
                roots[i]  = paramsPartQ->GetParams()[i]->GetRootOfUnity();
            }

            auto params = DCRTPoly::Params(paramsPartQ->GetCyclotomicOrder(), moduli, roots);

            partsCt[part] = DCRTPoly(std::make_shared<ParmType>(params), Format::EVALUATION, true);
        }
        else {
            partsCt[part] = DCRTPoly(cryptoParams->GetParamsPartQ(part), Format::EVALUATION, true);
        }

        usint sizePartQl   = partsCt[part].GetNumOfElements();
        usint startPartIdx = alpha * part;
        for (uint32_t i = 0, idx = startPartIdx; i < sizePartQl; i++, idx++) {
            partsCt[part].SetElementAtIndex(i, c.GetElementAtIndex(idx));
        }
    }

    std::vector<DCRTPoly> partsCtCompl(numPartQl);
    std::vector<DCRTPoly> partsCtExt(numPartQl);

    for (uint32_t part = 0; part < numPartQl; part++) {
        auto partCtClone = partsCt[part].Clone();
        partCtClone.SetFormat(Format::COEFFICIENT);

        uint32_t sizePartQl = partsCt[part].GetNumOfElements();
        partsCtCompl[part]  = partCtClone.ApproxSwitchCRTBasis(
             cryptoParams->GetParamsPartQ(part), cryptoParams->GetParamsComplPartQ(sizeQl - 1, part),
             cryptoParams->GetPartQlHatInvModq(part, sizePartQl - 1),
             cryptoParams->GetPartQlHatInvModqPrecon(part, sizePartQl - 1),
             cryptoParams->GetPartQlHatModp(sizeQl - 1, part),
             cryptoParams->GetmodComplPartqBarrettMu(sizeQl - 1, part));

        partsCtCompl[part].SetFormat(Format::EVALUATION);

        partsCtExt[part] = DCRTPoly(paramsQlP, Format::EVALUATION, true);

        usint startPartIdx = alpha * part;
        usint endPartIdx   = startPartIdx + sizePartQl;
        for (usint i = 0; i < startPartIdx; i++) {
            partsCtExt[part].SetElementAtIndex(i, partsCtCompl[part].GetElementAtIndex(i));
        }
        for (usint i = startPartIdx, idx = 0; i < endPartIdx; i++, idx++) {
            partsCtExt[part].SetElementAtIndex(i, partsCt[part].GetElementAtIndex(idx));
        }
        for (usint i = endPartIdx; i < sizeQlP; ++i) {
            partsCtExt[part].SetElementAtIndex(i, partsCtCompl[part].GetElementAtIndex(i - sizePartQl));
        }
    }

    return std::make_shared<std::vector<DCRTPoly>>(std::move(partsCtExt));
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchDECOMP::EvalFastKeySwitchCore(
    const std::shared_ptr<std::vector<DCRTPoly>> digits, const EvalKey<DCRTPoly> evalKey,
    const std::shared_ptr<ParmType> paramsQl) const {
    std::cout << "Using KeySwitchDECOMP::EvalFastKeySwitchCore" << std::endl;
    
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(evalKey->GetCryptoParameters());

    std::shared_ptr<std::vector<DCRTPoly>> cTilda = EvalFastKeySwitchCoreExt(digits, evalKey, paramsQl);

    PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    DCRTPoly ct0 = (*cTilda)[0].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                              cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                              cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                              cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                              cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

    DCRTPoly ct1 = (*cTilda)[1].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                              cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                              cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                              cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                              cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

    return std::make_shared<std::vector<DCRTPoly>>(std::initializer_list<DCRTPoly>{std::move(ct0), std::move(ct1)});
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchDECOMP::EvalFastKeySwitchCoreExt(
    const std::shared_ptr<std::vector<DCRTPoly>> digits, const EvalKey<DCRTPoly> evalKey,
    const std::shared_ptr<ParmType> paramsQl) const {
    std::cout << "Using KeySwitchDECOMP::EvalFastKeySwitchCoreExt" << std::endl;
    
    const auto cryptoParams         = std::dynamic_pointer_cast<CryptoParametersRNS>(evalKey->GetCryptoParameters());
    const std::vector<DCRTPoly>& bv = evalKey->GetBVector();
    const std::vector<DCRTPoly>& av = evalKey->GetAVector();

    const std::shared_ptr<ParmType> paramsP   = cryptoParams->GetParamsP();
    const std::shared_ptr<ParmType> paramsQlP = (*digits)[0].GetParams();

    size_t sizeQl  = paramsQl->GetParams().size();
    size_t sizeQlP = paramsQlP->GetParams().size();
    size_t sizeQ   = cryptoParams->GetElementParams()->GetParams().size();

    DCRTPoly cTilda0(paramsQlP, Format::EVALUATION, true);
    DCRTPoly cTilda1(paramsQlP, Format::EVALUATION, true);

    for (uint32_t j = 0; j < digits->size(); j++) {
        const DCRTPoly& cj = (*digits)[j];
        const DCRTPoly& bj = bv[j];
        const DCRTPoly& aj = av[j];

        for (usint i = 0; i < sizeQl; i++) {
            const auto& cji = cj.GetElementAtIndex(i);
            const auto& aji = aj.GetElementAtIndex(i);
            const auto& bji = bj.GetElementAtIndex(i);

            cTilda0.SetElementAtIndex(i, cTilda0.GetElementAtIndex(i) + cji * bji);
            cTilda1.SetElementAtIndex(i, cTilda1.GetElementAtIndex(i) + cji * aji);
        }
        for (usint i = sizeQl, idx = sizeQ; i < sizeQlP; i++, idx++) {
            const auto& cji = cj.GetElementAtIndex(i);
            const auto& aji = aj.GetElementAtIndex(idx);
            const auto& bji = bj.GetElementAtIndex(idx);

            cTilda0.SetElementAtIndex(i, cTilda0.GetElementAtIndex(i) + cji * bji);
            cTilda1.SetElementAtIndex(i, cTilda1.GetElementAtIndex(i) + cji * aji);
        }
    }

    return std::make_shared<std::vector<DCRTPoly>>(
        std::initializer_list<DCRTPoly>{std::move(cTilda0), std::move(cTilda1)});
}

}  // namespace lbcrypto