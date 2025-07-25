/**
* @brief Implementation of BATCHED key switching
*/
#define PROFILE

#include "keyswitch/keyswitch-batched.h"

#include "key/privatekey.h"
#include "key/publickey.h"
#include "key/evalkeyrelin.h"
#include "schemerns/rns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "cryptocontext.h"
#include <iostream>

namespace lbcrypto {

EvalKey<DCRTPoly> KeySwitchBATCHED::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                       const PrivateKey<DCRTPoly> newKey) const {
   std::cout << "Using KeySwitchBATCHED::KeySwitchGenInternal (2 keys)" << std::endl;
   return KeySwitchBATCHED::KeySwitchGenInternal(oldKey, newKey, nullptr);
}

EvalKey<DCRTPoly> KeySwitchBATCHED::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                       const PrivateKey<DCRTPoly> newKey,
                                                       const EvalKey<DCRTPoly> ekPrev) const {
   std::cout << "Using KeySwitchBATCHED::KeySwitchGenInternal (3 params)" << std::endl;
   
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
   //std::cout << "Debug: sizeQ = " << sizeQ << std::endl;
   
   size_t sizeQP = paramsQP->GetParams().size();
   //std::cout << "Debug: sizeQP = " << sizeQP << std::endl;

   DCRTPoly sOld = oldKey->GetPrivateElement();
   DCRTPoly sNew = newKey->GetPrivateElement().Clone();

   // skNew is currently in basis Q. This extends it to basis QP.
   sNew.SetFormat(Format::COEFFICIENT);
   //std::cout << "Debug: Set sNew format to COEFFICIENT" << std::endl;

   DCRTPoly sNewExt(paramsQP, Format::COEFFICIENT, true);
   //std::cout << "Debug: Created sNewExt" << std::endl;

   // The part with basis Q
   for (size_t i = 0; i < sizeQ; i++) {
       sNewExt.SetElementAtIndex(i, sNew.GetElementAtIndex(i));
   }
   //std::cout << "Debug: Filled sNewExt with Q part" << std::endl;

   // The part with basis P
   for (size_t j = sizeQ; j < sizeQP; j++) {
       if(j >= paramsQP->GetParams().size()) {
           std::cout << "Error: j=" << j << " is out of bounds for paramsQP (size=" << paramsQP->GetParams().size() << ")" << std::endl;
           OPENFHE_THROW("Index out of bounds in paramsQP->GetParams()");
       }
       
       const NativeInteger& pj = paramsQP->GetParams()[j]->GetModulus();
       const NativeInteger& rootj = paramsQP->GetParams()[j]->GetRootOfUnity();
       
       if(sNew.GetNumOfElements() == 0) {
           std::cout << "Error: sNew has no elements" << std::endl;
           OPENFHE_THROW("sNew has no elements");
       }
       
       auto sNew0 = sNew.GetElementAtIndex(0);
       sNew0.SwitchModulus(pj, rootj, 0, 0);
       sNewExt.SetElementAtIndex(j, std::move(sNew0));
   }
   //std::cout << "Debug: Filled sNewExt with P part" << std::endl;

   sNewExt.SetFormat(Format::EVALUATION);
   //std::cout << "Debug: Set sNewExt format to EVALUATION" << std::endl;

   const auto ns = cryptoParams->GetNoiseScale();
   const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
   DugType dug;

   size_t numPartQ = cryptoParams->GetNumPartQ();
   //std::cout << "Debug: numPartQ = " << numPartQ << std::endl;

   std::vector<DCRTPoly> av(numPartQ);
   std::vector<DCRTPoly> bv(numPartQ);

   std::vector<NativeInteger> PModq = cryptoParams->GetPModq();
   size_t numPerPartQ = cryptoParams->GetNumPerPartQ();
   //std::cout << "Debug: numPerPartQ = " << numPerPartQ << std::endl;

   for (size_t part = 0; part < numPartQ; ++part) {
       //std::cout << "Debug: Processing part " << part << std::endl;
       
       DCRTPoly a = (ekPrev == nullptr) ? 
                    DCRTPoly(dug, paramsQP, Format::EVALUATION) :  // single-key HE
                    ekPrev->GetAVector()[part];                    // threshold HE
                    
       DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
       DCRTPoly b(paramsQP, Format::EVALUATION, true);

       // starting and ending position of current part
       size_t startPartIdx = numPerPartQ * part;
       size_t endPartIdx = (sizeQ > (startPartIdx + numPerPartQ)) ? 
                         (startPartIdx + numPerPartQ) : sizeQ;
       
       //std::cout << "Debug: startPartIdx = " << startPartIdx << ", endPartIdx = " << endPartIdx << std::endl;

       for (size_t i = 0; i < sizeQP; ++i) {
           auto ai = a.GetElementAtIndex(i);
           auto ei = e.GetElementAtIndex(i);
           auto sNewi = sNewExt.GetElementAtIndex(i);

           if (i < startPartIdx || i >= endPartIdx) {
               b.SetElementAtIndex(i, -ai * sNewi + ns * ei);
           }
           else {
               // P * sOld is only applied for the current part
               if(i >= sOld.GetNumOfElements()) {
                   std::cout << "Error: i=" << i << " is out of bounds for sOld (size=" << sOld.GetNumOfElements() << ")" << std::endl;
                   OPENFHE_THROW("Index out of bounds in sOld");
               }
               if(i >= PModq.size()) {
                   std::cout << "Error: i=" << i << " is out of bounds for PModq (size=" << PModq.size() << ")" << std::endl;
                   OPENFHE_THROW("Index out of bounds in PModq");
               }
               
               auto sOldi = sOld.GetElementAtIndex(i);
               b.SetElementAtIndex(i, -ai * sNewi + PModq[i] * sOldi + ns * ei);
           }
       }
       //std::cout << "Debug: Completed inner loop for part " << part << std::endl;

       av[part] = a;
       bv[part] = b;
   }
   //std::cout << "Debug: Completed all parts" << std::endl;

   ek->SetAVector(std::move(av));
   ek->SetBVector(std::move(bv));
   ek->SetKeyTag(newKey->GetKeyTag());
   //std::cout << "Debug: Set vectors in ek" << std::endl;
   
   return ek;
}

EvalKey<DCRTPoly> KeySwitchBATCHED::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                       const PublicKey<DCRTPoly> newKey) const {
   std::cout << "Using KeySwitchBATCHED::KeySwitchGenInternal (oldKey, newPubKey)" << std::endl;
   
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
   //std::cout << "Debug: sizeQ = " << sizeQ << std::endl;
   
   usint sizeQP = paramsQP->GetParams().size();
   //std::cout << "Debug: sizeQP = " << sizeQP << std::endl;

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
   //std::cout << "Debug: numPartQ = " << numPartQ << std::endl;

   std::vector<DCRTPoly> av(numPartQ);
   std::vector<DCRTPoly> bv(numPartQ);

   std::vector<NativeInteger> PModq = cryptoParams->GetPModq();
   usint numPerPartQ = cryptoParams->GetNumPerPartQ();
   //std::cout << "Debug: numPerPartQ = " << numPerPartQ << std::endl;

   for (usint part = 0; part < numPartQ; part++) {
       //std::cout << "Debug: Processing part " << part << std::endl;
       
       DCRTPoly u = (cryptoParams->GetSecretKeyDist() == GAUSSIAN) ? 
                     DCRTPoly(dgg, paramsQP, Format::EVALUATION) :
                     DCRTPoly(tug, paramsQP, Format::EVALUATION);

       DCRTPoly e0(dgg, paramsQP, Format::EVALUATION);
       DCRTPoly e1(dgg, paramsQP, Format::EVALUATION);

       DCRTPoly a(paramsQP, Format::EVALUATION, true);
       DCRTPoly b(paramsQP, Format::EVALUATION, true);

       // starting and ending position of current part
       usint startPartIdx = numPerPartQ * part;
       usint endPartIdx = (sizeQ > startPartIdx + numPerPartQ) ? 
                        (startPartIdx + numPerPartQ) : sizeQ;
       
       //std::cout << "Debug: startPartIdx = " << startPartIdx << ", endPartIdx = " << endPartIdx << std::endl;

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
               if(i >= sOld.GetNumOfElements()) {
                   std::cout << "Error: i=" << i << " is out of bounds for sOld (size=" << sOld.GetNumOfElements() << ")" << std::endl;
                   OPENFHE_THROW("Index out of bounds in sOld");
               }
               if(i >= PModq.size()) {
                   std::cout << "Error: i=" << i << " is out of bounds for PModq (size=" << PModq.size() << ")" << std::endl;
                   OPENFHE_THROW("Index out of bounds in PModq");
               }
               
               auto sOldi = sOld.GetElementAtIndex(i);
               b.SetElementAtIndex(i, newp0i * ui + ns * e0i + PModq[i] * sOldi);
           }
       }
       //std::cout << "Debug: Completed inner loop for part " << part << std::endl;

       av[part] = a;
       bv[part] = b;
   }
   //std::cout << "Debug: Completed all parts" << std::endl;

   ek->SetAVector(std::move(av));
   ek->SetBVector(std::move(bv));
   ek->SetKeyTag(newKey->GetKeyTag());
   //std::cout << "Debug: Set vectors in ek" << std::endl;

   return ek;
}

void KeySwitchBATCHED::KeySwitchInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> ek) const {
   std::cout << "Using KeySwitchBATCHED::KeySwitchInPlace" << std::endl;
   
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
   
   //std::cout << "Debug: ciphertext size = " << cv.size() << std::endl;
   
   std::shared_ptr<std::vector<DCRTPoly>> ba;
   if(cv.size() == 2) {
       //std::cout << "Debug: Calling KeySwitchCore with cv[1]" << std::endl;
       ba = KeySwitchCore(cv[1], ek);
   } else {
       //std::cout << "Debug: Calling KeySwitchCore with cv[2]" << std::endl;
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
   //std::cout << "Debug: KeySwitchInPlace completed" << std::endl;
}

Ciphertext<DCRTPoly> KeySwitchBATCHED::KeySwitchExt(ConstCiphertext<DCRTPoly> ciphertext, bool addFirst) const {
   std::cout << "Using KeySwitchBATCHED::KeySwitchExt" << std::endl;
   
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
   //std::cout << "Debug: sizeQl = " << sizeQl << std::endl;
   
   usint sizeCv = cv.size();
   //std::cout << "Debug: sizeCv = " << sizeCv << std::endl;
   
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
   //std::cout << "Debug: Created result elements" << std::endl;

   Ciphertext<DCRTPoly> result = ciphertext->CloneZero();
   result->SetElements(std::move(resultElements));
   //std::cout << "Debug: KeySwitchExt completed" << std::endl;
   return result;
}

Ciphertext<DCRTPoly> KeySwitchBATCHED::KeySwitchDown(ConstCiphertext<DCRTPoly> ciphertext) const {
   std::cout << "Using KeySwitchBATCHED::KeySwitchDown" << std::endl;
   
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

   // TODO : (Andrey) precompute paramsQl in cryptoparameters
   usint sizeQl = paramsQlP->GetParams().size() - paramsP->GetParams().size();
   std::vector<NativeInteger> moduliQ(sizeQl);
   std::vector<NativeInteger> rootsQ(sizeQl);
   for (size_t i = 0; i < sizeQl; i++) {
       moduliQ[i] = paramsQlP->GetParams()[i]->GetModulus();
       rootsQ[i] = paramsQlP->GetParams()[i]->GetRootOfUnity();
   }
   auto paramsQl = std::make_shared<typename DCRTPoly::Params>(2 * paramsQlP->GetRingDimension(), moduliQ, rootsQ);
   //std::cout << "Debug: Created paramsQl" << std::endl;

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
   //std::cout << "Debug: Performed ApproxModDown" << std::endl;

   Ciphertext<DCRTPoly> result = ciphertext->CloneZero();
   result->SetElements(std::vector<DCRTPoly>{std::move(ct0), std::move(ct1)});
   //std::cout << "Debug: KeySwitchDown completed" << std::endl;
   return result;
}

DCRTPoly KeySwitchBATCHED::KeySwitchDownFirstElement(ConstCiphertext<DCRTPoly> ciphertext) const {
    std::cout << "Using KeySwitchBATCHED::KeySwitchDownFirstElement" << std::endl;
    
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
    //std::cout << "Debug: Created paramsQl" << std::endl;

    PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    DCRTPoly cv0 = cTilda[0].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                            cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                            cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                            cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                            cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());
    //std::cout << "Debug: KeySwitchDownFirstElement completed" << std::endl;

    return cv0;
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchBATCHED::KeySwitchCore(const DCRTPoly& a,
                                                                     const EvalKey<DCRTPoly> evalKey) const {
    std::cout << "Using KeySwitchBATCHED::KeySwitchCore" << std::endl;
    
    if(evalKey == nullptr) {
        std::cout << "Error: evalKey is nullptr" << std::endl;
        OPENFHE_THROW("evalKey is nullptr");
    }
    
    auto cryptoParams = evalKey->GetCryptoParameters();
    if(cryptoParams == nullptr) {
        std::cout << "Error: cryptoParams from evalKey is nullptr" << std::endl;
        OPENFHE_THROW("cryptoParams from evalKey is nullptr");
    }
    
    auto digits = EvalKeySwitchPrecomputeCore(a, cryptoParams);
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

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchBATCHED::EvalKeySwitchPrecomputeCore(
    const DCRTPoly& c, std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParamsBase) const {
    std::cout << "Using KeySwitchBATCHED::EvalKeySwitchPrecomputeCore" << std::endl;
    
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
    //std::cout << "Debug: sizeQl = " << sizeQl << std::endl;

    size_t sizeP = paramsP->GetParams().size();
    //std::cout << "Debug: sizeP = " << sizeP << std::endl;

    size_t sizeQlP = sizeQl + sizeP;
    //std::cout << "Debug: sizeQlP = " << sizeQlP << std::endl;

    uint32_t alpha = cryptoParams->GetNumPerPartQ();
    //std::cout << "Debug: alpha = " << alpha << std::endl;

    // The number of digits of the current ciphertext
    uint32_t numPartQl = ceil((static_cast<double>(sizeQl)) / alpha);
    if (numPartQl > cryptoParams->GetNumberOfQPartitions()) {
        numPartQl = cryptoParams->GetNumberOfQPartitions();
    }
    //std::cout << "Debug: numPartQl = " << numPartQl << std::endl;

    std::vector<DCRTPoly> partsCt(numPartQl);
    //std::cout << "Debug: Created partsCt with size " << numPartQl << std::endl;

    // Digit decomposition
    // Zero-padding and split
    for (uint32_t part = 0; part < numPartQl; part++) {
        //std::cout << "Debug: Processing digit decomposition part " << part << std::endl;
        
        if (part == numPartQl - 1) {
            auto paramsPartQ = cryptoParams->GetParamsPartQ(part);
            if(paramsPartQ == nullptr) {
                std::cout << "Error: paramsPartQ for part " << part << " is nullptr" << std::endl;
                OPENFHE_THROW("paramsPartQ is nullptr");
            }

            uint32_t sizePartQl = sizeQl - alpha * part;
            //std::cout << "Debug: sizePartQl = " << sizePartQl << std::endl;

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
        //std::cout << "Debug: sizePartQl = " << sizePartQl << ", startPartIdx = " << startPartIdx << std::endl;
        
        for (uint32_t i = 0, idx = startPartIdx; i < sizePartQl; i++, idx++) {
            if(idx >= c.GetNumOfElements()) {
                std::cout << "Error: idx=" << idx << " is out of bounds for c (size=" << c.GetNumOfElements() << ")" << std::endl;
                OPENFHE_THROW("Index out of bounds in c");
            }
            
            partsCt[part].SetElementAtIndex(i, c.GetElementAtIndex(idx));
        }
    }
    //std::cout << "Debug: Completed digit decomposition" << std::endl;

    std::vector<DCRTPoly> partsCtCompl(numPartQl);
    std::vector<DCRTPoly> partsCtExt(numPartQl);

    for (uint32_t part = 0; part < numPartQl; part++) {
        //std::cout << "Debug: Processing CRT basis switching part " << part << std::endl;
        
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
        
        auto partQlHatInvModq = cryptoParams->GetPartQlHatInvModq(part, sizePartQl - 1);
        auto partQlHatInvModqPrecon = cryptoParams->GetPartQlHatInvModqPrecon(part, sizePartQl - 1);
        auto partQlHatModp = cryptoParams->GetPartQlHatModp(sizeQl - 1, part);
        auto modComplPartqBarrettMu = cryptoParams->GetmodComplPartqBarrettMu(sizeQl - 1, part);

        partsCtCompl[part] = partCtClone.ApproxSwitchCRTBasis(
            paramsPartQ, paramsComplPartQ,
            partQlHatInvModq, partQlHatInvModqPrecon,
            partQlHatModp, modComplPartqBarrettMu);

        partsCtCompl[part].SetFormat(Format::EVALUATION);
        //std::cout << "Debug: Completed ApproxSwitchCRTBasis for part " << part << std::endl;

        partsCtExt[part] = DCRTPoly(paramsQlP, Format::EVALUATION, true);

        usint startPartIdx = alpha * part;
        usint endPartIdx = startPartIdx + sizePartQl;
        
        //std::cout << "Debug: startPartIdx = " << startPartIdx << ", endPartIdx = " << endPartIdx << std::endl;
        
        for (usint i = 0; i < startPartIdx; i++) {
            if(i >= partsCtCompl[part].GetNumOfElements()) {
                std::cout << "Error: i=" << i << " is out of bounds for partsCtCompl[" << part << "] (size=" << partsCtCompl[part].GetNumOfElements() << ")" << std::endl;
                OPENFHE_THROW("Index out of bounds in partsCtCompl");
            }
            
            partsCtExt[part].SetElementAtIndex(i, partsCtCompl[part].GetElementAtIndex(i));
        }
        
        for (usint i = startPartIdx, idx = 0; i < endPartIdx; i++, idx++) {
            if(idx >= partsCt[part].GetNumOfElements()) {
                std::cout << "Error: idx=" << idx << " is out of bounds for partsCt[" << part << "] (size=" << partsCt[part].GetNumOfElements() << ")" << std::endl;
                OPENFHE_THROW("Index out of bounds in partsCt");
            }
            
            partsCtExt[part].SetElementAtIndex(i, partsCt[part].GetElementAtIndex(idx));
        }
        
        for (usint i = endPartIdx; i < sizeQlP; ++i) {
            usint adjIdx = i - sizePartQl;
            if(adjIdx >= partsCtCompl[part].GetNumOfElements()) {
                std::cout << "Error: adjusted idx=" << adjIdx << " is out of bounds for partsCtCompl[" << part << "] (size=" << partsCtCompl[part].GetNumOfElements() << ")" << std::endl;
                OPENFHE_THROW("Index out of bounds in partsCtCompl");
            }
            
            partsCtExt[part].SetElementAtIndex(i, partsCtCompl[part].GetElementAtIndex(adjIdx));
        }
    }
    //std::cout << "Debug: EvalKeySwitchPrecomputeCore completed" << std::endl;

    return std::make_shared<std::vector<DCRTPoly>>(std::move(partsCtExt));
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchBATCHED::EvalFastKeySwitchCore(
    const std::shared_ptr<std::vector<DCRTPoly>> digits, const EvalKey<DCRTPoly> evalKey,
    const std::shared_ptr<ParmType> paramsQl) const {
    std::cout << "Using KeySwitchBATCHED::EvalFastKeySwitchCore" << std::endl;

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

    std::shared_ptr<std::vector<DCRTPoly>> cTilda = EvalFastKeySwitchCoreExt(digits, evalKey, paramsQl);
    if(cTilda == nullptr) {
        std::cout << "Error: EvalFastKeySwitchCoreExt returned nullptr" << std::endl;
        OPENFHE_THROW("EvalFastKeySwitchCoreExt returned nullptr");
    }

    if(cTilda->size() < 2) {
        std::cout << "Error: cTilda has size " << cTilda->size() << " (expected at least 2)" << std::endl;
        OPENFHE_THROW("cTilda has insufficient size");
    }

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
    //std::cout << "Debug: EvalFastKeySwitchCore completed" << std::endl;

    return std::make_shared<std::vector<DCRTPoly>>(std::initializer_list<DCRTPoly>{std::move(ct0), std::move(ct1)});
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchBATCHED::EvalFastKeySwitchCoreExt(
    const std::shared_ptr<std::vector<DCRTPoly>> digits, const EvalKey<DCRTPoly> evalKey,
    const std::shared_ptr<ParmType> paramsQl) const {
    std::cout << "Using KeySwitchBATCHED::EvalFastKeySwitchCoreExt" << std::endl;
 
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
    //std::cout << "Debug: sizeQl = " << sizeQl << std::endl;
 
    size_t sizeQlP = paramsQlP->GetParams().size();
    //std::cout << "Debug: sizeQlP = " << sizeQlP << std::endl;
 
    size_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();
    //std::cout << "Debug: sizeQ = " << sizeQ << std::endl;
 
    DCRTPoly cTilda0(paramsQlP, Format::EVALUATION, true);
    DCRTPoly cTilda1(paramsQlP, Format::EVALUATION, true);
 
    for (uint32_t j = 0; j < digits->size(); j++) {
        //std::cout << "Debug: Processing digit " << j << " of " << digits->size() << std::endl;
        
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
            if(i >= cj.GetNumOfElements()) {
                std::cout << "Warning: i=" << i << " is out of bounds for cj (size=" << cj.GetNumOfElements() << "), skipping" << std::endl;
                continue;
            }
            
            if(i >= aj.GetNumOfElements()) {
                std::cout << "Warning: i=" << i << " is out of bounds for aj (size=" << aj.GetNumOfElements() << "), skipping" << std::endl;
                continue;
            }
            
            if(i >= bj.GetNumOfElements()) {
                std::cout << "Warning: i=" << i << " is out of bounds for bj (size=" << bj.GetNumOfElements() << "), skipping" << std::endl;
                continue;
            }
        
            const auto& cji = cj.GetElementAtIndex(i);
            const auto& aji = aj.GetElementAtIndex(i);
            const auto& bji = bj.GetElementAtIndex(i);
 
            cTilda0.SetElementAtIndex(i, cTilda0.GetElementAtIndex(i) + cji * bji);
            cTilda1.SetElementAtIndex(i, cTilda1.GetElementAtIndex(i) + cji * aji);
        }
        
        for (usint i = sizeQl, idx = sizeQ; i < sizeQlP; i++, idx++) {
            if(i >= cj.GetNumOfElements()) {
                std::cout << "Warning: i=" << i << " is out of bounds for cj (size=" << cj.GetNumOfElements() << "), skipping" << std::endl;
                continue;
            }
            
            if(idx >= aj.GetNumOfElements()) {
                std::cout << "Warning: idx=" << idx << " is out of bounds for aj (size=" << aj.GetNumOfElements() << "), skipping" << std::endl;
                continue;
            }
            
            if(idx >= bj.GetNumOfElements()) {
                std::cout << "Warning: idx=" << idx << " is out of bounds for bj (size=" << bj.GetNumOfElements() << "), skipping" << std::endl;
                continue;
            }
        
            const auto& cji = cj.GetElementAtIndex(i);
            const auto& aji = aj.GetElementAtIndex(idx);
            const auto& bji = bj.GetElementAtIndex(idx);
 
            cTilda0.SetElementAtIndex(i, cTilda0.GetElementAtIndex(i) + cji * bji);
            cTilda1.SetElementAtIndex(i, cTilda1.GetElementAtIndex(i) + cji * aji);
        }
    }
    
    // std::cout << "Debug: Final state check in EvalFastKeySwitchCoreExt" << std::endl;
    // std::cout << "Debug: cTilda0 elements: " << cTilda0.GetNumOfElements() 
    //           << ", format: " << static_cast<int>(cTilda0.GetFormat()) << std::endl;
    // std::cout << "Debug: cTilda1 elements: " << cTilda1.GetNumOfElements() 
    //           << ", format: " << static_cast<int>(cTilda1.GetFormat()) << std::endl;
    
    if(cTilda0.GetNumOfElements() > 0) {
        auto firstElement = cTilda0.GetElementAtIndex(0);
        //std::cout << "Debug: cTilda0 first element isValid: " << !firstElement.IsEmpty() << std::endl;
    }
    
    if(cTilda1.GetNumOfElements() > 0) {
        auto firstElement = cTilda1.GetElementAtIndex(0);
        //std::cout << "Debug: cTilda1 first element isValid: " << !firstElement.IsEmpty() << std::endl;
    }
    
    auto result = std::make_shared<std::vector<DCRTPoly>>(
        std::initializer_list<DCRTPoly>{cTilda0, cTilda1});
    //std::cout << "Debug: Result vector created with size: " << result->size() << std::endl;
    
    //std::cout << "Debug: EvalFastKeySwitchCoreExt completed" << std::endl;
 
    return result;
 }

}  // namespace lbcrypto