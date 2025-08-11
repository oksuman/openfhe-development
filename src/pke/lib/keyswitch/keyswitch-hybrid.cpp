//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/**
* Hybrid key switching implementation. See
* Appendix of https://eprint.iacr.org/2021/204 for details.
*/
#define PROFILE

#include "keyswitch/keyswitch-hybrid.h"

#include "key/privatekey.h"
#include "key/publickey.h"
#include "key/evalkeyrelin.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "ciphertext.h"

namespace lbcrypto {

EvalKey<DCRTPoly> KeySwitchHYBRID::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                       const PrivateKey<DCRTPoly> newKey) const {
   return KeySwitchHYBRID::KeySwitchGenInternal(oldKey, newKey, nullptr);
}

EvalKey<DCRTPoly> KeySwitchHYBRID::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                       const PrivateKey<DCRTPoly> newKey,
                                                       const EvalKey<DCRTPoly> ekPrev) const {
   
   if(oldKey == nullptr) {
       std::cout << "Error: oldKey is nullptr" << std::endl;
       OPENFHE_THROW("oldKey is nullptr");
   }
   
   if(newKey == nullptr) {
       std::cout << "Error: newKey is nullptr" << std::endl;
       OPENFHE_THROW("newKey is nullptr");
   }
   
   EvalKeyRelin<DCRTPoly> ek(std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext()));

   const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(newKey->GetCryptoParameters());
   if(cryptoParams == nullptr) {
       std::cout << "Error: cryptoParams is nullptr" << std::endl;
       OPENFHE_THROW("cryptoParams is nullptr");
   }

   const std::shared_ptr<ParmType> paramsQ = cryptoParams->GetElementParams();
   if(paramsQ == nullptr) {
       std::cout << "Error: paramsQ is nullptr" << std::endl;
       OPENFHE_THROW("paramsQ is nullptr");
   }
   
   const std::shared_ptr<ParmType> paramsQP = cryptoParams->GetParamsQP();
   if(paramsQP == nullptr) {
       std::cout << "Error: paramsQP is nullptr" << std::endl;
       OPENFHE_THROW("paramsQP is nullptr");
   }

   size_t sizeQ = paramsQ->GetParams().size();
   
   size_t sizeQP = paramsQP->GetParams().size();

   DCRTPoly sOld = oldKey->GetPrivateElement();
   DCRTPoly sNew = newKey->GetPrivateElement().Clone();

   sNew.SetFormat(Format::COEFFICIENT);

   DCRTPoly sNewExt(paramsQP, Format::COEFFICIENT, true);

   for (size_t i = 0; i < sizeQ; i++) {
       sNewExt.SetElementAtIndex(i, sNew.GetElementAtIndex(i));
   }

   for (size_t j = sizeQ; j < sizeQP; j++) {
       const NativeInteger& pj = paramsQP->GetParams()[j]->GetModulus();
       const NativeInteger& rootj = paramsQP->GetParams()[j]->GetRootOfUnity();
       auto sNew0 = sNew.GetElementAtIndex(0);
       sNew0.SwitchModulus(pj, rootj, 0, 0);
       sNewExt.SetElementAtIndex(j, std::move(sNew0));
   }

   sNewExt.SetFormat(Format::EVALUATION);

   const auto ns = cryptoParams->GetNoiseScale();
   const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
   DugType dug;

   size_t numPartQ = cryptoParams->GetNumPartQ();

   std::vector<DCRTPoly> av(numPartQ);
   std::vector<DCRTPoly> bv(numPartQ);

   std::vector<NativeInteger> PModq = cryptoParams->GetPModq();
   size_t numPerPartQ = cryptoParams->GetNumPerPartQ();

   for (size_t part = 0; part < numPartQ; ++part) {

       DCRTPoly a = (ekPrev == nullptr) ? 
                    DCRTPoly(dug, paramsQP, Format::EVALUATION) :  // single-key HE
                    ekPrev->GetAVector()[part];                    // threshold HE
                   
       DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
       DCRTPoly b(paramsQP, Format::EVALUATION, true);

       size_t startPartIdx = numPerPartQ * part;
       size_t endPartIdx = (sizeQ > (startPartIdx + numPerPartQ)) ? 
                         (startPartIdx + numPerPartQ) : sizeQ;
       

       for (size_t i = 0; i < sizeQP; ++i) {
           auto ai = a.GetElementAtIndex(i);
           auto ei = e.GetElementAtIndex(i);
           auto sNewi = sNewExt.GetElementAtIndex(i);

           if (i < startPartIdx || i >= endPartIdx) {
               b.SetElementAtIndex(i, -ai * sNewi + ns * ei);
           }
           else {
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

EvalKey<DCRTPoly> KeySwitchHYBRID::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                       const PublicKey<DCRTPoly> newKey) const {
   
   if(oldKey == nullptr) {
       std::cout << "Error: oldKey is nullptr" << std::endl;
       OPENFHE_THROW("oldKey is nullptr");
   }
   
   if(newKey == nullptr) {
       std::cout << "Error: newKey is nullptr" << std::endl;
       OPENFHE_THROW("newKey is nullptr");
   }
   
   EvalKeyRelin<DCRTPoly> ek = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext());

   const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(newKey->GetCryptoParameters());
   if(cryptoParams == nullptr) {
       std::cout << "Error: cryptoParams is nullptr" << std::endl;
       OPENFHE_THROW("cryptoParams is nullptr");
   }

   const std::shared_ptr<ParmType> paramsQ = cryptoParams->GetElementParams();
   if(paramsQ == nullptr) {
       std::cout << "Error: paramsQ is nullptr" << std::endl;
       OPENFHE_THROW("paramsQ is nullptr");
   }
   
   const std::shared_ptr<ParmType> paramsQP = cryptoParams->GetParamsQP();
   if(paramsQP == nullptr) {
       std::cout << "Error: paramsQP is nullptr" << std::endl;
       OPENFHE_THROW("paramsQP is nullptr");
   }

   usint sizeQ = paramsQ->GetParams().size();

   
   usint sizeQP = paramsQP->GetParams().size();

   DCRTPoly sOld = oldKey->GetPrivateElement();
   if(sOld.GetNumOfElements() == 0) {
       std::cout << "Error: sOld has no elements" << std::endl;
       OPENFHE_THROW("sOld has no elements");
   }

   DCRTPoly newp0 = newKey->GetPublicElements().at(0);
   DCRTPoly newp1 = newKey->GetPublicElements().at(1);

   const auto ns = cryptoParams->GetNoiseScale();
   const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
   TugType tug;

   auto numPartQ = cryptoParams->GetNumPartQ();

   std::vector<DCRTPoly> av(numPartQ);
   std::vector<DCRTPoly> bv(numPartQ);

   std::vector<NativeInteger> PModq = cryptoParams->GetPModq();
   usint numPerPartQ = cryptoParams->GetNumPerPartQ();

   for (usint part = 0; part < numPartQ; part++) {
       
       DCRTPoly u = (cryptoParams->GetSecretKeyDist() == GAUSSIAN) ? 
                    DCRTPoly(dgg, paramsQP, Format::EVALUATION) :
                    DCRTPoly(tug, paramsQP, Format::EVALUATION);

       DCRTPoly e0(dgg, paramsQP, Format::EVALUATION);
       DCRTPoly e1(dgg, paramsQP, Format::EVALUATION);

       DCRTPoly a(paramsQP, Format::EVALUATION, true);
       DCRTPoly b(paramsQP, Format::EVALUATION, true);

       usint startPartIdx = numPerPartQ * part;
       usint endPartIdx = (sizeQ > startPartIdx + numPerPartQ) ? 
                        (startPartIdx + numPerPartQ) : sizeQ;
       

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

void KeySwitchHYBRID::KeySwitchInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> ek) const {
   
   if(ciphertext == nullptr) {
       std::cout << "Error: ciphertext is nullptr" << std::endl;
       OPENFHE_THROW("ciphertext is nullptr");
   }
   
   if(ek == nullptr) {
       std::cout << "Error: ek is nullptr" << std::endl;
       OPENFHE_THROW("ek is nullptr");
   }
   
   std::vector<DCRTPoly>& cv = ciphertext->GetElements();
   if(cv.empty()) {
       std::cout << "Error: ciphertext elements vector is empty" << std::endl;
       OPENFHE_THROW("ciphertext elements vector is empty");
   }

   
   std::shared_ptr<std::vector<DCRTPoly>> ba;
   if(cv.size() == 2) {
       ba = KeySwitchCore(cv[1], ek);
   } else {
       ba = KeySwitchCore(cv[2], ek);
   }
   
   if(ba == nullptr) {
       std::cout << "Error: KeySwitchCore returned nullptr" << std::endl;
       OPENFHE_THROW("KeySwitchCore returned nullptr");
   }
   
   if(ba->size() < 2) {
       std::cout << "Error: KeySwitchCore result has size " << ba->size() << " (expected at least 2)" << std::endl;
       OPENFHE_THROW("KeySwitchCore result has insufficient size");
   }

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

Ciphertext<DCRTPoly> KeySwitchHYBRID::KeySwitchExt(ConstCiphertext<DCRTPoly> ciphertext, bool addFirst) const {
   
   if(ciphertext == nullptr) {
       std::cout << "Error: ciphertext is nullptr" << std::endl;
       OPENFHE_THROW("ciphertext is nullptr");
   }
   
   const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
   if(cryptoParams == nullptr) {
       std::cout << "Error: cryptoParams is nullptr" << std::endl;
       OPENFHE_THROW("cryptoParams is nullptr");
   }

   const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
   if(cv.empty()) {
       std::cout << "Error: ciphertext elements vector is empty" << std::endl;
       OPENFHE_THROW("ciphertext elements vector is empty");
   }

   const auto paramsQl = cv[0].GetParams();
   if(paramsQl == nullptr) {
       std::cout << "Error: paramsQl is nullptr" << std::endl;
       OPENFHE_THROW("paramsQl is nullptr");
   }
   
   const auto paramsP = cryptoParams->GetParamsP();
   if(paramsP == nullptr) {
       std::cout << "Error: paramsP is nullptr" << std::endl;
       OPENFHE_THROW("paramsP is nullptr");
   }
   
   const auto paramsQlP = cv[0].GetExtendedCRTBasis(paramsP);
   if(paramsQlP == nullptr) {
       std::cout << "Error: paramsQlP is nullptr" << std::endl;
       OPENFHE_THROW("paramsQlP is nullptr");
   }

   size_t sizeQl = paramsQl->GetParams().size();
   
   usint sizeCv = cv.size();
   
   std::vector<DCRTPoly> resultElements(sizeCv);
   for (usint k = 0; k < sizeCv; k++) {
       resultElements[k] = DCRTPoly(paramsQlP, Format::EVALUATION, true);
       if ((addFirst) || (k > 0)) {
           auto PModq = cryptoParams->GetPModq();
           if(PModq.empty()) {
               std::cout << "Error: PModq is empty" << std::endl;
               OPENFHE_THROW("PModq is empty");
           }
           
           auto cMult = cv[k].TimesNoCheck(PModq);
           for (usint i = 0; i < sizeQl; i++) {
               resultElements[k].SetElementAtIndex(i, std::move(cMult.GetElementAtIndex(i)));
           }
       }
   }
   Ciphertext<DCRTPoly> result = ciphertext->CloneZero();
   result->SetElements(std::move(resultElements));
   return result;
}

Ciphertext<DCRTPoly> KeySwitchHYBRID::KeySwitchDown(ConstCiphertext<DCRTPoly> ciphertext) const {
   
   if(ciphertext == nullptr) {
       std::cout << "Error: ciphertext is nullptr" << std::endl;
       OPENFHE_THROW("ciphertext is nullptr");
   }
   
   const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
   if(cryptoParams == nullptr) {
       std::cout << "Error: cryptoParams is nullptr" << std::endl;
       OPENFHE_THROW("cryptoParams is nullptr");
   }

   const auto paramsP = cryptoParams->GetParamsP();
   if(paramsP == nullptr) {
       std::cout << "Error: paramsP is nullptr" << std::endl;
       OPENFHE_THROW("paramsP is nullptr");
   }
   
   const auto paramsQlP = ciphertext->GetElements()[0].GetParams();
   if(paramsQlP == nullptr) {
       std::cout << "Error: paramsQlP is nullptr" << std::endl;
       OPENFHE_THROW("paramsQlP is nullptr");
   }

   usint sizeQl = paramsQlP->GetParams().size() - paramsP->GetParams().size();
   std::vector<NativeInteger> moduliQ(sizeQl);
   std::vector<NativeInteger> rootsQ(sizeQl);
   for (size_t i = 0; i < sizeQl; i++) {
       moduliQ[i] = paramsQlP->GetParams()[i]->GetModulus();
       rootsQ[i] = paramsQlP->GetParams()[i]->GetRootOfUnity();
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

DCRTPoly KeySwitchHYBRID::KeySwitchDownFirstElement(ConstCiphertext<DCRTPoly> ciphertext) const {
   
   if(ciphertext == nullptr) {
       std::cout << "Error: ciphertext is nullptr" << std::endl;
       OPENFHE_THROW("ciphertext is nullptr");
   }
   
   const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
   if(cryptoParams == nullptr) {
       std::cout << "Error: cryptoParams is nullptr" << std::endl;
       OPENFHE_THROW("cryptoParams is nullptr");
   }

   const std::vector<DCRTPoly>& cTilda = ciphertext->GetElements();
   if(cTilda.empty()) {
       std::cout << "Error: ciphertext elements vector is empty" << std::endl;
       OPENFHE_THROW("ciphertext elements vector is empty");
   }

   const auto paramsP = cryptoParams->GetParamsP();
   if(paramsP == nullptr) {
       std::cout << "Error: paramsP is nullptr" << std::endl;
       OPENFHE_THROW("paramsP is nullptr");
   }
   
   const auto paramsQlP = cTilda[0].GetParams();
   if(paramsQlP == nullptr) {
       std::cout << "Error: paramsQlP is nullptr" << std::endl;
       OPENFHE_THROW("paramsQlP is nullptr");
   }

   usint sizeQl = paramsQlP->GetParams().size() - paramsP->GetParams().size();
   std::vector<NativeInteger> moduliQ(sizeQl);
   std::vector<NativeInteger> rootsQ(sizeQl);
   for (size_t i = 0; i < sizeQl; i++) {
       moduliQ[i] = paramsQlP->GetParams()[i]->GetModulus();
       rootsQ[i] = paramsQlP->GetParams()[i]->GetRootOfUnity();
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

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchHYBRID::KeySwitchCore(const DCRTPoly& a,
                                                                     const EvalKey<DCRTPoly> evalKey) const {
   
   if(evalKey == nullptr) {
       std::cout << "Error: evalKey is nullptr" << std::endl;
       OPENFHE_THROW("evalKey is nullptr");
   }
   
   auto cryptoParams = evalKey->GetCryptoParameters();
   if(cryptoParams == nullptr) {
       std::cout << "Error: cryptoParams from evalKey is nullptr" << std::endl;
       OPENFHE_THROW("cryptoParams from evalKey is nullptr");
   }
   
    // === Timing ===
    auto start = std::chrono::high_resolution_clock::now();
    auto digits = EvalKeySwitchPrecomputeCore(a, cryptoParams);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    ksprofile::AddModUp(duration_us / 1000.0);  // ModUp + decomposition
    // std::cout << "[TIMING] Digit decomposition took " << duration_us / 1000.0 << " ms" << std::endl;
    // === Timing ===

   if(digits == nullptr) {
       std::cout << "Error: EvalKeySwitchPrecomputeCore returned nullptr" << std::endl;
       OPENFHE_THROW("EvalKeySwitchPrecomputeCore returned nullptr");
   }
   
   auto paramsQl = a.GetParams();
   if(paramsQl == nullptr) {
       std::cout << "Error: paramsQl from a is nullptr" << std::endl;
       OPENFHE_THROW("paramsQl from a is nullptr");
   }
   
   return EvalFastKeySwitchCore(digits, evalKey, paramsQl);
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchHYBRID::EvalKeySwitchPrecomputeCore(
    const DCRTPoly& c, std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParamsBase) const {
    
    if(cryptoParamsBase == nullptr) {
        std::cout << "Error: cryptoParamsBase is nullptr" << std::endl;
        OPENFHE_THROW("cryptoParamsBase is nullptr");
    }
 
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoParamsBase);
    if(cryptoParams == nullptr) {
        std::cout << "Error: cryptoParams is nullptr" << std::endl;
        OPENFHE_THROW("cryptoParams is nullptr");
    }
 
    const std::shared_ptr<ParmType> paramsQl = c.GetParams();
    if(paramsQl == nullptr) {
        std::cout << "Error: paramsQl is nullptr" << std::endl;
        OPENFHE_THROW("paramsQl is nullptr");
    }
 
    const std::shared_ptr<ParmType> paramsP = cryptoParams->GetParamsP();
    if(paramsP == nullptr) {
        std::cout << "Error: paramsP is nullptr" << std::endl;
        OPENFHE_THROW("paramsP is nullptr");
    }
 
    const std::shared_ptr<ParmType> paramsQlP = c.GetExtendedCRTBasis(paramsP);
    if(paramsQlP == nullptr) {
        std::cout << "Error: paramsQlP is nullptr" << std::endl;
        OPENFHE_THROW("paramsQlP is nullptr");
    }
 
    size_t sizeQl = paramsQl->GetParams().size();
 
    size_t sizeP = paramsP->GetParams().size();

    size_t sizeQlP = sizeQl + sizeP;
 
    uint32_t alpha = cryptoParams->GetNumPerPartQ();
 
    // The number of digits of the current ciphertext
    uint32_t numPartQl = ceil((static_cast<double>(sizeQl)) / alpha);
    if (numPartQl > cryptoParams->GetNumberOfQPartitions()) {
        numPartQl = cryptoParams->GetNumberOfQPartitions();
    }
 
    std::vector<DCRTPoly> partsCt(numPartQl);

    // Digit decomposition
    // Zero-padding and split
    for (uint32_t part = 0; part < numPartQl; part++) {
        
        if (part == numPartQl - 1) {
            auto paramsPartQ = cryptoParams->GetParamsPartQ(part);
            if(paramsPartQ == nullptr) {
                std::cout << "Error: paramsPartQ for part " << part << " is nullptr" << std::endl;
                OPENFHE_THROW("paramsPartQ is nullptr");
            }
 
            uint32_t sizePartQl = sizeQl - alpha * part;
 
            std::vector<NativeInteger> moduli(sizePartQl);
            std::vector<NativeInteger> roots(sizePartQl);
 
            for (uint32_t i = 0; i < sizePartQl; i++) {
                moduli[i] = paramsPartQ->GetParams()[i]->GetModulus();
                roots[i] = paramsPartQ->GetParams()[i]->GetRootOfUnity();
            }
 
            auto params = DCRTPoly::Params(paramsPartQ->GetCyclotomicOrder(), moduli, roots);
 
            partsCt[part] = DCRTPoly(std::make_shared<ParmType>(params), Format::EVALUATION, true);
        }
        else {
            auto paramsPartQ = cryptoParams->GetParamsPartQ(part);
            if(paramsPartQ == nullptr) {
                std::cout << "Error: paramsPartQ for part " << part << " is nullptr" << std::endl;
                OPENFHE_THROW("paramsPartQ is nullptr");
            }
            
            partsCt[part] = DCRTPoly(paramsPartQ, Format::EVALUATION, true);
        }
 
        usint sizePartQl = partsCt[part].GetNumOfElements();
        usint startPartIdx = alpha * part;
        
        for (uint32_t i = 0, idx = startPartIdx; i < sizePartQl; i++, idx++) {
            if(idx >= c.GetNumOfElements()) {
                std::cout << "Error: idx=" << idx << " is out of bounds for c (size=" << c.GetNumOfElements() << ")" << std::endl;
                OPENFHE_THROW("Index out of bounds in c");
            }
            
            partsCt[part].SetElementAtIndex(i, c.GetElementAtIndex(idx));
        }
    }
 
    std::vector<DCRTPoly> partsCtCompl(numPartQl);
    std::vector<DCRTPoly> partsCtExt(numPartQl);
 
    for (uint32_t part = 0; part < numPartQl; part++) {
        
        auto partCtClone = partsCt[part].Clone();
        partCtClone.SetFormat(Format::COEFFICIENT);
 
        uint32_t sizePartQl = partsCt[part].GetNumOfElements();
        auto paramsPartQ = cryptoParams->GetParamsPartQ(part);
        if(paramsPartQ == nullptr) {
            std::cout << "Error: paramsPartQ for part " << part << " is nullptr" << std::endl;
            OPENFHE_THROW("paramsPartQ is nullptr");
        }
        
        auto paramsComplPartQ = cryptoParams->GetParamsComplPartQ(sizeQl - 1, part);
        if(paramsComplPartQ == nullptr) {
            std::cout << "Error: paramsComplPartQ for part " << part << " is nullptr" << std::endl;
            OPENFHE_THROW("paramsComplPartQ is nullptr");
        }
        
        partsCtCompl[part] = partCtClone.ApproxSwitchCRTBasis(
             cryptoParams->GetParamsPartQ(part), cryptoParams->GetParamsComplPartQ(sizeQl - 1, part),
             cryptoParams->GetPartQlHatInvModq(part, sizePartQl - 1),
             cryptoParams->GetPartQlHatInvModqPrecon(part, sizePartQl - 1),
             cryptoParams->GetPartQlHatModp(sizeQl - 1, part),
             cryptoParams->GetmodComplPartqBarrettMu(sizeQl - 1, part));
 
        partsCtCompl[part].SetFormat(Format::EVALUATION);
 
        partsCtExt[part] = DCRTPoly(paramsQlP, Format::EVALUATION, true);
 
        usint startPartIdx = alpha * part;
        usint endPartIdx = startPartIdx + sizePartQl;
        
        
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
 
 std::shared_ptr<std::vector<DCRTPoly>> KeySwitchHYBRID::EvalFastKeySwitchCore(
    const std::shared_ptr<std::vector<DCRTPoly>> digits, const EvalKey<DCRTPoly> evalKey,
    const std::shared_ptr<ParmType> paramsQl) const {
 
    if(digits == nullptr) {
        std::cout << "Error: digits is nullptr" << std::endl;
        OPENFHE_THROW("digits is nullptr");
    }
 
    if(evalKey == nullptr) {
        std::cout << "Error: evalKey is nullptr" << std::endl;
        OPENFHE_THROW("evalKey is nullptr");
    }
 
    if(paramsQl == nullptr) {
        std::cout << "Error: paramsQl is nullptr" << std::endl;
        OPENFHE_THROW("paramsQl is nullptr");
    }
 
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(evalKey->GetCryptoParameters());
    if(cryptoParams == nullptr) {
        std::cout << "Error: cryptoParams is nullptr" << std::endl;
        OPENFHE_THROW("cryptoParams is nullptr");
    }
 
       // --- Inner product Timing ---
    auto start_ks = std::chrono::high_resolution_clock::now();
    std::shared_ptr<std::vector<DCRTPoly>> cTilda =
        EvalFastKeySwitchCoreExt(digits, evalKey, paramsQl);
    auto end_ks = std::chrono::high_resolution_clock::now();
    auto duration_ks = std::chrono::duration_cast<std::chrono::microseconds>(end_ks - start_ks).count();
    ksprofile::AddInner(duration_ks / 1000.0);
    // std::cout << "[TIMING] EvalFastKeySwitchCoreExt took " << duration_ks / 1000.0 << " ms" << std::endl;
    
    if(cTilda == nullptr) {
        std::cout << "Error: EvalFastKeySwitchCoreExt returned nullptr" << std::endl;
        OPENFHE_THROW("EvalFastKeySwitchCoreExt returned nullptr");
    }
    
    if(cTilda->size() < 2) {
        std::cout << "Error: cTilda has size " << cTilda->size() << " (expected at least 2)" << std::endl;
        OPENFHE_THROW("cTilda has insufficient size");
    }
 
    PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    
    // --- Mod down Timing ---
    auto start_moddown = std::chrono::high_resolution_clock::now();
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

    auto end_moddown = std::chrono::high_resolution_clock::now();
    auto duration_moddown =
        std::chrono::duration_cast<std::chrono::microseconds>(end_moddown - start_moddown).count();
    ksprofile::AddModDown(duration_moddown / 1000.0);
    // std::cout << "[TIMING] ApproxModDown (both elements) took " << duration_moddown / 1000.0 << " ms" << std::endl;

    return std::make_shared<std::vector<DCRTPoly>>(std::initializer_list<DCRTPoly>{std::move(ct0), std::move(ct1)});
 }
 
 std::shared_ptr<std::vector<DCRTPoly>> KeySwitchHYBRID::EvalFastKeySwitchCoreExt(
    const std::shared_ptr<std::vector<DCRTPoly>> digits, const EvalKey<DCRTPoly> evalKey,
    const std::shared_ptr<ParmType> paramsQl) const {
 
    if(digits == nullptr) {
        std::cout << "Error: digits is nullptr" << std::endl;
        OPENFHE_THROW("digits is nullptr");
    }
 
    if(evalKey == nullptr) {
        std::cout << "Error: evalKey is nullptr" << std::endl;
        OPENFHE_THROW("evalKey is nullptr");
    }
 
    if(paramsQl == nullptr) {
        std::cout << "Error: paramsQl is nullptr" << std::endl;
        OPENFHE_THROW("paramsQl is nullptr");
    }
 
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(evalKey->GetCryptoParameters());
    if(cryptoParams == nullptr) {
        std::cout << "Error: cryptoParams is nullptr" << std::endl;
        OPENFHE_THROW("cryptoParams is nullptr");
    }
    
    const std::vector<DCRTPoly>& bv = evalKey->GetBVector();
    const std::vector<DCRTPoly>& av = evalKey->GetAVector();
 
    if(bv.empty()) {
        std::cout << "Error: bv is empty" << std::endl;
        OPENFHE_THROW("bv is empty");
    }
 
    if(av.empty()) {
        std::cout << "Error: av is empty" << std::endl;
        OPENFHE_THROW("av is empty");
    }
 
    const std::shared_ptr<ParmType> paramsP = cryptoParams->GetParamsP();
    if(paramsP == nullptr) {
        std::cout << "Error: paramsP is nullptr" << std::endl;
        OPENFHE_THROW("paramsP is nullptr");
    }
 
    const std::shared_ptr<ParmType> paramsQlP = (*digits)[0].GetParams();
    if(paramsQlP == nullptr) {
        std::cout << "Error: paramsQlP is nullptr" << std::endl;
        OPENFHE_THROW("paramsQlP is nullptr");
    }
 
    size_t sizeQl = paramsQl->GetParams().size();
 
    size_t sizeQlP = paramsQlP->GetParams().size();
 
    size_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();

    DCRTPoly cTilda0(paramsQlP, Format::EVALUATION, true);
    DCRTPoly cTilda1(paramsQlP, Format::EVALUATION, true);
 
    for (uint32_t j = 0; j < digits->size(); j++) {
        
        if(j >= bv.size()) {
            std::cout << "Error: j=" << j << " is out of bounds for bv (size=" << bv.size() << ")" << std::endl;
            OPENFHE_THROW("Index out of bounds in bv");
        }
        
        if(j >= av.size()) {
            std::cout << "Error: j=" << j << " is out of bounds for av (size=" << av.size() << ")" << std::endl;
            OPENFHE_THROW("Index out of bounds in av");
        }
        
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
    
    if(cTilda0.GetNumOfElements() > 0) {
        auto firstElement = cTilda0.GetElementAtIndex(0);
    }
    
    if(cTilda1.GetNumOfElements() > 0) {
        auto firstElement = cTilda1.GetElementAtIndex(0);
    }
    
    auto result = std::make_shared<std::vector<DCRTPoly>>(
        std::initializer_list<DCRTPoly>{cTilda0, cTilda1});
 
    return result;
 }
 
 }  // namespace lbcrypto