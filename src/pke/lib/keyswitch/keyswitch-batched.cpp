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
#include <chrono>

namespace lbcrypto {

EvalKey<DCRTPoly> KeySwitchBATCHED::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                       const PrivateKey<DCRTPoly> newKey) const {
//    std::cout << "Using KeySwitchBATCHED::KeySwitchGenInternal (2 keys)" << std::endl;
   return KeySwitchBATCHED::KeySwitchGenInternal(oldKey, newKey, nullptr);
}

EvalKey<DCRTPoly> KeySwitchBATCHED::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                       const PrivateKey<DCRTPoly> newKey,
                                                       const EvalKey<DCRTPoly> ekPrev) const {
//    std::cout << "Using KeySwitchBATCHED::KeySwitchGenInternal (3 params)" << std::endl;
   
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
//    std::cout << "Using KeySwitchBATCHED::KeySwitchGenInternal (oldKey, newPubKey)" << std::endl;
   
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
//    std::cout << "Using KeySwitchBATCHED::KeySwitchInPlace" << std::endl;
   
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

// s^2 not considered, only autormophism
void KeySwitchBATCHED::BatchedKeySwitchInPlace(
    Ciphertext<DCRTPoly>& ciphertext,
    const std::vector<DCRTPoly>& cvToSwitch,
    const std::vector<EvalKey<DCRTPoly>>& evalKeyVec) const {

    if (!ciphertext) {
        OPENFHE_THROW("ciphertext is nullptr");
    }

    std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    std::vector<int32_t>& keyDeps = ciphertext->GetElementKeyIndexVector();

    if (cv.empty() || keyDeps.size() != cv.size()) {
        OPENFHE_THROW("Ciphertext structure invalid");
    }

    if (!cvToSwitch.empty()) {
        auto switched = BatchedKeySwitchCore(cvToSwitch, evalKeyVec);
        if (!switched || switched->size() != 2) {
            OPENFHE_THROW("BatchedKeySwitchCore returned invalid result");
        }

        // Add to ct0
        cv[0] += (*switched)[0];

        if (cv.size() == 2) {
            cv[1] += (*switched)[1];
        }
        else {
            cv.push_back((*switched)[1]);
            keyDeps.push_back(CiphertextImpl<DCRTPoly>::KEY_DEP_S);
        }
    }

    // Ensure keyDeps[0] is set properly (even if switched was empty)
    keyDeps[0] = CiphertextImpl<DCRTPoly>::KEY_DEP_CONSTANT;
    if (cv.size() == 2)
        keyDeps[1] = CiphertextImpl<DCRTPoly>::KEY_DEP_S;
}



Ciphertext<DCRTPoly> KeySwitchBATCHED::KeySwitchExt(ConstCiphertext<DCRTPoly> ciphertext, bool addFirst) const {
//    std::cout << "Using KeySwitchBATCHED::KeySwitchExt" << std::endl;
   
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
//    std::cout << "Using KeySwitchBATCHED::KeySwitchDown" << std::endl;
   
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

std::shared_ptr<std::vector<DCRTPoly>> 
KeySwitchBATCHED::BatchedKeySwitchCore(
    const std::vector<DCRTPoly>& cv,
    const std::vector<EvalKey<DCRTPoly>>& evalKeyVec) const {


    if (cv.size() != evalKeyVec.size()) {
        OPENFHE_THROW("BatchedKeySwitchCore: mismatch between cv and evalKeyVec size");
    }

    if (cv.empty()) {
        OPENFHE_THROW("BatchedKeySwitchCore: empty input ciphertext vector");
    }

    auto cryptoParams = evalKeyVec[0]->GetCryptoParameters();
    if (!cryptoParams) {
        OPENFHE_THROW("BatchedKeySwitchCore: cryptoParams is nullptr");
    }

    // === Timing ===
    auto start = std::chrono::high_resolution_clock::now();
    auto allDigits = EvalBatchedKeySwitchPrecomputeCore(cv, cryptoParams);
    if (!allDigits || allDigits->size() != cv.size()) {
        OPENFHE_THROW("BatchedKeySwitchCore: EvalKeySwitchPrecomputeCore returned invalid result");
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    ksprofile::AddModUp(duration_us / 1000.0);  // ModUp + decomposition

    // std::cout << "[TIMING] Digit decomposition took " << duration_us / 1000.0 << " ms" << std::endl;
    // === Timing ===

    // Perform fast batched key switching
    const auto paramsQl = cv[0].GetParams();
    if (!paramsQl) {
        OPENFHE_THROW("BatchedKeySwitchCore: paramsQl is nullptr");
    }

    return EvalFastBatchedKeySwitchCore(allDigits, evalKeyVec, paramsQl);
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchBATCHED::EvalKeySwitchPrecomputeCore(
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
        
        auto partQlHatInvModq = cryptoParams->GetPartQlHatInvModq(part, sizePartQl - 1);
        auto partQlHatInvModqPrecon = cryptoParams->GetPartQlHatInvModqPrecon(part, sizePartQl - 1);
        auto partQlHatModp = cryptoParams->GetPartQlHatModp(sizeQl - 1, part);
        auto modComplPartqBarrettMu = cryptoParams->GetmodComplPartqBarrettMu(sizeQl - 1, part);

        partsCtCompl[part] = partCtClone.ApproxSwitchCRTBasis(
            paramsPartQ, paramsComplPartQ,
            partQlHatInvModq, partQlHatInvModqPrecon,
            partQlHatModp, modComplPartqBarrettMu);

        partsCtCompl[part].SetFormat(Format::EVALUATION);
    
        partsCtExt[part] = DCRTPoly(paramsQlP, Format::EVALUATION, true);

        usint startPartIdx = alpha * part;
        usint endPartIdx = startPartIdx + sizePartQl;
        
        
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

    return std::make_shared<std::vector<DCRTPoly>>(std::move(partsCtExt));
}

// std::shared_ptr<std::vector<std::vector<DCRTPoly>>>
// KeySwitchBATCHED::EvalBatchedKeySwitchPrecomputeCore(
//     const std::vector<DCRTPoly>& cv,
//     std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParamsBase) const {

//     // std::cout << "Using KeySwitchBATCHED::EvalBatchedKeySwitchPrecomputeCore (batch-aware)" << std::endl;

//     if (!cryptoParamsBase) {
//         OPENFHE_THROW("cryptoParamsBase is nullptr");
//     }

//     auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoParamsBase);
//     if (!cryptoParams) {
//         OPENFHE_THROW("cryptoParams cast failed");
//     }

//     if (cv.empty()) {
//         OPENFHE_THROW("EvalBatchedKeySwitchPrecomputeCore: input ciphertext vector is empty");
//     }

//     const auto paramsQl = cv[0].GetParams();
//     const auto paramsP = cryptoParams->GetParamsP();
//     const auto paramsQlP = cv[0].GetExtendedCRTBasis(paramsP);
//     if (!paramsQl || !paramsP || !paramsQlP) {
//         OPENFHE_THROW("Missing CRT parameter(s)");
//     }

//     const size_t sizeQl = paramsQl->GetParams().size();
//     const size_t sizeP = paramsP->GetParams().size();
//     const size_t sizeQlP = sizeQl + sizeP;
//     const uint32_t alpha = cryptoParams->GetNumPerPartQ();
//     uint32_t numPartQl = ceil((static_cast<double>(sizeQl)) / alpha);
//     if (numPartQl > cryptoParams->GetNumberOfQPartitions()) {
//         numPartQl = cryptoParams->GetNumberOfQPartitions();
//     }

//     auto result = std::make_shared<std::vector<std::vector<DCRTPoly>>>();
//     result->reserve(cv.size());

//     for (const auto& c : cv) {
//         std::vector<DCRTPoly> partsCt(numPartQl);

//         for (uint32_t part = 0; part < numPartQl; ++part) {
//             auto paramsPartQ = cryptoParams->GetParamsPartQ(part);
//             if (!paramsPartQ) {
//                 OPENFHE_THROW("paramsPartQ is nullptr");
//             }

//             if (part == numPartQl - 1) {
//                 const uint32_t sizePartQl = sizeQl - alpha * part;
//                 std::vector<NativeInteger> moduli(sizePartQl), roots(sizePartQl);
//                 for (uint32_t i = 0; i < sizePartQl; ++i) {
//                     moduli[i] = paramsPartQ->GetParams()[i]->GetModulus();
//                     roots[i] = paramsPartQ->GetParams()[i]->GetRootOfUnity();
//                 }
//                 auto params = DCRTPoly::Params(paramsPartQ->GetCyclotomicOrder(), moduli, roots);
//                 partsCt[part] = DCRTPoly(std::make_shared<ParmType>(params), Format::EVALUATION, true);
//             } else {
//                 partsCt[part] = DCRTPoly(paramsPartQ, Format::EVALUATION, true);
//             }

//             const usint sizePartQl = partsCt[part].GetNumOfElements();
//             const usint startPartIdx = alpha * part;
//             for (usint i = 0, idx = startPartIdx; i < sizePartQl; ++i, ++idx) {
//                 partsCt[part].SetElementAtIndex(i, c.GetElementAtIndex(idx));
//             }
//         }

//         std::vector<DCRTPoly> partsCtExt(numPartQl);

//         for (uint32_t part = 0; part < numPartQl; ++part) {
//             auto partCtClone = partsCt[part].Clone();
//             partCtClone.SetFormat(Format::COEFFICIENT);

//             const auto sizePartQl = partsCt[part].GetNumOfElements();
//             auto paramsPartQ = cryptoParams->GetParamsPartQ(part);
//             auto paramsComplPartQ = cryptoParams->GetParamsComplPartQ(sizeQl - 1, part);
//             auto partQlHatInvModq = cryptoParams->GetPartQlHatInvModq(part, sizePartQl - 1);
//             auto partQlHatInvModqPrecon = cryptoParams->GetPartQlHatInvModqPrecon(part, sizePartQl - 1);
//             auto partQlHatModp = cryptoParams->GetPartQlHatModp(sizeQl - 1, part);
//             auto modComplPartqBarrettMu = cryptoParams->GetmodComplPartqBarrettMu(sizeQl - 1, part);

//             auto partsCtCompl = partCtClone.ApproxSwitchCRTBasis(
//                 paramsPartQ, paramsComplPartQ,
//                 partQlHatInvModq, partQlHatInvModqPrecon,
//                 partQlHatModp, modComplPartqBarrettMu);

//             partsCtCompl.SetFormat(Format::EVALUATION);

//             DCRTPoly ext(paramsQlP, Format::EVALUATION, true);
//             const usint startPartIdx = alpha * part;
//             const usint endPartIdx = startPartIdx + sizePartQl;

//             for (usint i = 0; i < startPartIdx; ++i)
//                 ext.SetElementAtIndex(i, partsCtCompl.GetElementAtIndex(i));

//             for (usint i = startPartIdx, idx = 0; i < endPartIdx; ++i, ++idx)
//                 ext.SetElementAtIndex(i, partsCt[part].GetElementAtIndex(idx));

//             for (usint i = endPartIdx; i < sizeQlP; ++i) {
//                 usint adjIdx = i - sizePartQl;
//                 ext.SetElementAtIndex(i, partsCtCompl.GetElementAtIndex(adjIdx));
//             }

//             partsCtExt[part] = std::move(ext);
//         }

//         result->emplace_back(std::move(partsCtExt));
//     }

//     return result;
// }

std::shared_ptr<std::vector<std::vector<DCRTPoly>>>
KeySwitchBATCHED::EvalBatchedKeySwitchPrecomputeCore(
    const std::vector<DCRTPoly>& cv,
    std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParamsBase) const {
        
    if (!cryptoParamsBase) {
        OPENFHE_THROW("cryptoParamsBase is nullptr");
    }

    auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoParamsBase);
    if (!cryptoParams) {
        OPENFHE_THROW("cryptoParams cast failed");
    }

    if (cv.empty()) {
        OPENFHE_THROW("EvalBatchedKeySwitchPrecomputeCore: input ciphertext vector is empty");
    }

    const auto paramsQl  = cv[0].GetParams();
    const auto paramsP   = cryptoParams->GetParamsP();
    const auto paramsQlP = cv[0].GetExtendedCRTBasis(paramsP);
    if (!paramsQl || !paramsP || !paramsQlP) {
        OPENFHE_THROW("Missing CRT parameter(s)");
    }

    const size_t   sizeQl  = paramsQl->GetParams().size();
    const size_t   sizeP   = paramsP->GetParams().size();
    const size_t   sizeQlP = sizeQl + sizeP;
    const uint32_t alpha   = cryptoParams->GetNumPerPartQ();
    uint32_t numPartQl     = ceil((static_cast<double>(sizeQl)) / alpha);
    if (numPartQl > cryptoParams->GetNumberOfQPartitions()) {
        numPartQl = cryptoParams->GetNumberOfQPartitions();
    }

    auto result = std::make_shared<std::vector<std::vector<DCRTPoly>>>();
    result->reserve(cv.size());

    for (const auto& c : cv) {
        std::vector<DCRTPoly> partsCt(numPartQl);

        for (uint32_t part = 0; part < numPartQl; ++part) {
            auto paramsPartQ = cryptoParams->GetParamsPartQ(part);
            if (!paramsPartQ) {
                OPENFHE_THROW("paramsPartQ is nullptr");
            }

            if (part == numPartQl - 1) {
                const uint32_t sizePartQlTail = sizeQl - alpha * part;
                std::vector<NativeInteger> moduli(sizePartQlTail), roots(sizePartQlTail);
                for (uint32_t i = 0; i < sizePartQlTail; ++i) {
                    moduli[i] = paramsPartQ->GetParams()[i]->GetModulus();
                    roots[i]  = paramsPartQ->GetParams()[i]->GetRootOfUnity();
                }
                auto params = DCRTPoly::Params(paramsPartQ->GetCyclotomicOrder(), moduli, roots);
                partsCt[part] = DCRTPoly(std::make_shared<ParmType>(params), Format::EVALUATION, true);
            } else {
                partsCt[part] = DCRTPoly(paramsPartQ, Format::EVALUATION, true);
            }

            const usint sizePartQlLocal = partsCt[part].GetNumOfElements();
            const usint startPartIdx    = alpha * part;
            for (usint i = 0, idx = startPartIdx; i < sizePartQlLocal; ++i, ++idx) {
                partsCt[part].SetElementAtIndex(i, c.GetElementAtIndex(idx));
            }
        }

        for (uint32_t part = 0; part < numPartQl; ++part) {
            auto paramsPartQ = cryptoParams->GetParamsPartQ(part);
            if (!paramsPartQ) {
                OPENFHE_THROW("paramsPartQ is nullptr (warm-up)");
            }
            auto paramsComplPartQ = cryptoParams->GetParamsComplPartQ(sizeQl - 1, part);
            if (!paramsComplPartQ) {
                OPENFHE_THROW("paramsComplPartQ is nullptr (warm-up)");
            }
            const usint sizePartQlLocal = (part == numPartQl - 1) ? (sizeQl - alpha * part) : alpha;
            (void)cryptoParams->GetPartQlHatInvModq(part, sizePartQlLocal ? (sizePartQlLocal - 1) : 0);
            (void)cryptoParams->GetPartQlHatInvModqPrecon(part, sizePartQlLocal ? (sizePartQlLocal - 1) : 0);
            (void)cryptoParams->GetPartQlHatModp(sizeQl - 1, part);
            (void)cryptoParams->GetmodComplPartqBarrettMu(sizeQl - 1, part);
        }

        std::vector<DCRTPoly> partsCtExt(numPartQl);

        #pragma omp parallel for schedule(static)
        for (uint32_t part = 0; part < numPartQl; ++part) {
            auto partCtClone = partsCt[part].Clone();
            partCtClone.SetFormat(Format::COEFFICIENT);

            const usint sizePartQlLocal = partsCt[part].GetNumOfElements();
            auto paramsPartQ            = cryptoParams->GetParamsPartQ(part);
            auto paramsComplPartQ       = cryptoParams->GetParamsComplPartQ(sizeQl - 1, part);
            auto partQlHatInvModq       = cryptoParams->GetPartQlHatInvModq(part, sizePartQlLocal - 1);
            auto partQlHatInvModqPrecon = cryptoParams->GetPartQlHatInvModqPrecon(part, sizePartQlLocal - 1);
            auto partQlHatModp          = cryptoParams->GetPartQlHatModp(sizeQl - 1, part);
            auto modComplPartqBarrettMu = cryptoParams->GetmodComplPartqBarrettMu(sizeQl - 1, part);

            auto partsCtCompl = partCtClone.ApproxSwitchCRTBasis(
                paramsPartQ, paramsComplPartQ,
                partQlHatInvModq, partQlHatInvModqPrecon,
                partQlHatModp, modComplPartqBarrettMu);

            partsCtCompl.SetFormat(Format::EVALUATION);

            DCRTPoly ext(paramsQlP, Format::EVALUATION, true);
            const usint startPartIdx = alpha * part;
            const usint endPartIdx   = startPartIdx + sizePartQlLocal;

            for (usint i = 0; i < startPartIdx; ++i)
                ext.SetElementAtIndex(i, partsCtCompl.GetElementAtIndex(i));

            for (usint i = startPartIdx, idx = 0; i < endPartIdx; ++i, ++idx)
                ext.SetElementAtIndex(i, partsCt[part].GetElementAtIndex(idx));

            for (usint i = endPartIdx; i < sizeQlP; ++i) {
                const usint adjIdx = i - sizePartQlLocal;
                ext.SetElementAtIndex(i, partsCtCompl.GetElementAtIndex(adjIdx));
            }

            partsCtExt[part] = std::move(ext);
        }

        result->emplace_back(std::move(partsCtExt));
    }
    return result;
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchBATCHED::EvalFastKeySwitchCore(
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

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchBATCHED::EvalFastBatchedKeySwitchCore(
    const std::shared_ptr<std::vector<std::vector<DCRTPoly>>>& digitsAll,
    const std::vector<EvalKey<DCRTPoly>>& evalKeyVec,
    const std::shared_ptr<ParmType> paramsQl) const {

    // std::cout << "Using KeySwitchBATCHED::EvalFastBatchedKeySwitchCore" << std::endl;

    if (!digitsAll) {
        OPENFHE_THROW("EvalFastBatchedKeySwitchCore: digitsAll is nullptr");
    }
    if (digitsAll->empty()) {
        OPENFHE_THROW("EvalFastBatchedKeySwitchCore: digitsAll is empty");
    }
    if (evalKeyVec.empty()) {
        OPENFHE_THROW("EvalFastBatchedKeySwitchCore: evalKeyVec is empty");
    }
    if (digitsAll->size() != evalKeyVec.size()) {
        OPENFHE_THROW("EvalFastBatchedKeySwitchCore: size mismatch between digitsAll and evalKeyVec");
    }
    if (!paramsQl) {
        OPENFHE_THROW("EvalFastBatchedKeySwitchCore: paramsQl is nullptr");
    }

    const EvalKey<DCRTPoly>  firstEK = evalKeyVec[0];
    if (!firstEK) {
        OPENFHE_THROW("EvalFastBatchedKeySwitchCore: first evalKey is nullptr");
    }

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(firstEK->GetCryptoParameters());
    if (!cryptoParams) {
        OPENFHE_THROW("EvalFastBatchedKeySwitchCore: cryptoParams cast failed");
    }

    // --- Inner product Timing ---
    auto start_ks = std::chrono::high_resolution_clock::now();
    auto cTildaPair = EvalFastBatchedKeySwitchCoreExt(digitsAll, evalKeyVec, paramsQl);
    if (!cTildaPair || cTildaPair->size() < 2) {
        OPENFHE_THROW("EvalFastBatchedKeySwitchCore: EvalFastBatchedKeySwitchCoreExt returned invalid result");
    }
    auto end_ks = std::chrono::high_resolution_clock::now();
    auto duration_ks = std::chrono::duration_cast<std::chrono::microseconds>(end_ks - start_ks).count();
    ksprofile::AddInner(duration_ks / 1000.0);
    // std::cout << "[TIMING] EvalFastBatchedKeySwitchCoreExt took " << duration_ks / 1000.0 << " ms" << std::endl;

    const PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    // --- Mod down Timing ---
    auto start_moddown = std::chrono::high_resolution_clock::now();
    DCRTPoly ct0 = (*cTildaPair)[0].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                                 cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                                 cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                                 cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                                 cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

    DCRTPoly ct1 = (*cTildaPair)[1].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                                 cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                                 cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                                 cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                                 cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

    auto end_moddown = std::chrono::high_resolution_clock::now();
    auto duration_moddown =
        std::chrono::duration_cast<std::chrono::microseconds>(end_moddown - start_moddown).count();
    ksprofile::AddModDown(duration_moddown / 1000.0);
    // std::cout << "[TIMING] ApproxModDown (both elements) took " << duration_moddown / 1000.0 << " ms" << std::endl;

    // Step 3: Return result
    return std::make_shared<std::vector<DCRTPoly>>(std::initializer_list<DCRTPoly>{std::move(ct0), std::move(ct1)});
}


std::shared_ptr<std::vector<DCRTPoly>> KeySwitchBATCHED::EvalFastKeySwitchCoreExt(
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

// No Parallelism
// std::shared_ptr<std::vector<DCRTPoly>> KeySwitchBATCHED::EvalFastBatchedKeySwitchCoreExt(
//     const std::shared_ptr<std::vector<std::vector<DCRTPoly>>>& digitsAll,
//     const std::vector<EvalKey<DCRTPoly>>& evalKeyVec,
//     const std::shared_ptr<ParmType> paramsQl) const {

//     // std::cout << "Using KeySwitchBATCHED::EvalFastBatchedKeySwitchCoreExt" << std::endl;

//     if (!digitsAll) {
//         std::cout << "Error: digitsAll is nullptr" << std::endl;
//         OPENFHE_THROW("digitsAll is nullptr");
//     }
//     if (digitsAll->empty()) {
//         std::cout << "Error: digitsAll is empty" << std::endl;
//         OPENFHE_THROW("digitsAll is empty");
//     }
//     if (evalKeyVec.empty()) {
//         std::cout << "Error: evalKeyVec is empty" << std::endl;
//         OPENFHE_THROW("evalKeyVec is empty");
//     }
//     if (digitsAll->size() != evalKeyVec.size()) {
//         std::cout << "Error: size mismatch: digitsAll=" << digitsAll->size()
//                   << " evalKeyVec=" << evalKeyVec.size() << std::endl;
//         OPENFHE_THROW("digitsAll and evalKeyVec size mismatch");
//     }
//     if (!paramsQl) {
//         std::cout << "Error: paramsQl is nullptr" << std::endl;
//         OPENFHE_THROW("paramsQl is nullptr");
//     }

//     const EvalKey<DCRTPoly> firstEK = evalKeyVec[0];
//     if (firstEK == nullptr) {
//         std::cout << "Error: first evalKey is nullptr" << std::endl;
//         OPENFHE_THROW("evalKey is nullptr");
//     }

//     const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(firstEK->GetCryptoParameters());
//     if (!cryptoParams) {
//         std::cout << "Error: cryptoParams cast failed" << std::endl;
//         OPENFHE_THROW("cryptoParams cast failed");
//     }

//     if ((*digitsAll)[0].empty()) {
//         std::cout << "Error: digitsAll[0] is empty" << std::endl;
//         OPENFHE_THROW("digitsAll[0] is empty");
//     }

//     const std::shared_ptr<ParmType> paramsQlP = (*digitsAll)[0][0].GetParams();
//     if (!paramsQlP) {
//         std::cout << "Error: paramsQlP is nullptr" << std::endl;
//         OPENFHE_THROW("paramsQlP is nullptr");
//     }

//     const size_t sizeQl  = paramsQl->GetParams().size();
//     const size_t sizeQlP = paramsQlP->GetParams().size();
//     const size_t sizeQ   = cryptoParams->GetElementParams()->GetParams().size();

//     DCRTPoly cTilda0(paramsQlP, Format::EVALUATION, true);
//     DCRTPoly cTilda1(paramsQlP, Format::EVALUATION, true);

//     for (size_t k = 0; k < evalKeyVec.size(); ++k) {
//         const auto ek = evalKeyVec[k];
//         if (ek == nullptr) {
//             std::cout << "Error: evalKeyVec[" << k << "] is nullptr" << std::endl;
//             OPENFHE_THROW("evalKey is nullptr");
//         }

//         const auto& digits = (*digitsAll)[k];
//         if (digits.empty()) {
//             std::cout << "Error: digitsAll[" << k << "] is empty" << std::endl;
//             OPENFHE_THROW("digitsAll[k] is empty");
//         }

//         const std::vector<DCRTPoly>& bv = ek->GetBVector();
//         const std::vector<DCRTPoly>& av = ek->GetAVector();

//         if (bv.empty()) {
//             std::cout << "Error: bv is empty at k=" << k << std::endl;
//             OPENFHE_THROW("bv is empty");
//         }
//         if (av.empty()) {
//             std::cout << "Error: av is empty at k=" << k << std::endl;
//             OPENFHE_THROW("av is empty");
//         }
//         if (bv.size() != digits.size() || av.size() != digits.size()) {
//             std::cout << "Error: digit/evalKey vector size mismatch at k=" << k
//                       << " digits=" << digits.size()
//                       << " bv=" << bv.size()
//                       << " av=" << av.size() << std::endl;
//             OPENFHE_THROW("digit/evalKey vector size mismatch");
//         }

//         for (uint32_t j = 0; j < digits.size(); ++j) {
//             const DCRTPoly& cj = digits[j];
//             const DCRTPoly& bj = bv[j];
//             const DCRTPoly& aj = av[j];

//             for (usint i = 0; i < sizeQl; ++i) {
//                 if (i >= cj.GetNumOfElements()) {
//                     std::cout << "Warning: i=" << i << " out of bounds for cj (size="
//                               << cj.GetNumOfElements() << "), skipping" << std::endl;
//                     continue;
//                 }
//                 if (i >= bj.GetNumOfElements()) {
//                     std::cout << "Warning: i=" << i << " out of bounds for bj (size="
//                               << bj.GetNumOfElements() << "), skipping" << std::endl;
//                     continue;
//                 }
//                 if (i >= aj.GetNumOfElements()) {
//                     std::cout << "Warning: i=" << i << " out of bounds for aj (size="
//                               << aj.GetNumOfElements() << "), skipping" << std::endl;
//                     continue;
//                 }

//                 const auto& cji = cj.GetElementAtIndex(i);
//                 const auto& bji = bj.GetElementAtIndex(i);
//                 const auto& aji = aj.GetElementAtIndex(i);

//                 cTilda0.SetElementAtIndex(i, cTilda0.GetElementAtIndex(i) + cji * bji);
//                 cTilda1.SetElementAtIndex(i, cTilda1.GetElementAtIndex(i) + cji * aji);
//             }

//             for (usint i = sizeQl, idx = sizeQ; i < sizeQlP; ++i, ++idx) {
//                 if (i >= cj.GetNumOfElements()) {
//                     std::cout << "Warning: i=" << i << " out of bounds for cj (size="
//                               << cj.GetNumOfElements() << "), skipping" << std::endl;
//                     continue;
//                 }
//                 if (idx >= bj.GetNumOfElements()) {
//                     std::cout << "Warning: idx=" << idx << " out of bounds for bj (size="
//                               << bj.GetNumOfElements() << "), skipping" << std::endl;
//                     continue;
//                 }
//                 if (idx >= aj.GetNumOfElements()) {
//                     std::cout << "Warning: idx=" << idx << " out of bounds for aj (size="
//                               << aj.GetNumOfElements() << "), skipping" << std::endl;
//                     continue;
//                 }

//                 const auto& cji = cj.GetElementAtIndex(i);
//                 const auto& bji = bj.GetElementAtIndex(idx);
//                 const auto& aji = aj.GetElementAtIndex(idx);

//                 cTilda0.SetElementAtIndex(i, cTilda0.GetElementAtIndex(i) + cji * bji);
//                 cTilda1.SetElementAtIndex(i, cTilda1.GetElementAtIndex(i) + cji * aji);
//             }
//         }
//     }

//     auto result = std::make_shared<std::vector<DCRTPoly>>(std::initializer_list<DCRTPoly>{cTilda0, cTilda1});
//     return result;
// }


std::shared_ptr<std::vector<DCRTPoly>> KeySwitchBATCHED::EvalFastBatchedKeySwitchCoreExt(
    const std::shared_ptr<std::vector<std::vector<DCRTPoly>>>& digitsAll,
    const std::vector<EvalKey<DCRTPoly>>& evalKeyVec,
    const std::shared_ptr<ParmType> paramsQl) const {
    if (!digitsAll) {
        OPENFHE_THROW("digitsAll is nullptr");
    }
    if (digitsAll->empty()) {
        OPENFHE_THROW("digitsAll is empty");
    }
    if (evalKeyVec.empty()) {
        OPENFHE_THROW("evalKeyVec is empty");
    }
    if (digitsAll->size() != evalKeyVec.size()) {
        OPENFHE_THROW("digitsAll and evalKeyVec size mismatch");
    }
    if (!paramsQl) {
        OPENFHE_THROW("paramsQl is nullptr");
    }

    const EvalKey<DCRTPoly> firstEK = evalKeyVec[0];
    if (firstEK == nullptr) {
        OPENFHE_THROW("evalKey is nullptr");
    }

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(firstEK->GetCryptoParameters());
    if (!cryptoParams) {
        OPENFHE_THROW("cryptoParams cast failed");
    }

    if ((*digitsAll)[0].empty()) {
        OPENFHE_THROW("digitsAll[0] is empty");
    }
    const std::shared_ptr<ParmType> paramsQlP = (*digitsAll)[0][0].GetParams();
    if (!paramsQlP) {
        OPENFHE_THROW("paramsQlP is nullptr");
    }

    const size_t sizeQl  = paramsQl->GetParams().size();
    const size_t sizeQlP = paramsQlP->GetParams().size();
    const size_t sizeQ   = cryptoParams->GetElementParams()->GetParams().size();

    for (size_t k = 0; k < evalKeyVec.size(); ++k) {
        const auto ek = evalKeyVec[k];
        if (ek == nullptr) {
            OPENFHE_THROW("evalKeyVec contains nullptr");
        }
        const auto& digits = (*digitsAll)[k];
        if (digits.empty()) {
            OPENFHE_THROW("digitsAll[k] is empty");
        }
        const std::vector<DCRTPoly>& bv = ek->GetBVector();
        const std::vector<DCRTPoly>& av = ek->GetAVector();

        if (bv.empty() || av.empty()) {
            OPENFHE_THROW("bv/av is empty");
        }
        // if (bv.size() != digits.size() || av.size() != digits.size()) {
        //     OPENFHE_THROW("digit/evalKey vector size mismatch");
        // }
    }

    DCRTPoly cTilda0(paramsQlP, Format::EVALUATION, true);
    DCRTPoly cTilda1(paramsQlP, Format::EVALUATION, true);

    #pragma omp parallel for schedule(static)
    for (usint i = 0; i < sizeQlP; ++i) {
        auto acc0 = cTilda0.GetElementAtIndex(i);
        auto acc1 = cTilda1.GetElementAtIndex(i);

        const bool inQl = (i < sizeQl);
        const usint bjajIdx = inQl ? i : (sizeQ + (i - sizeQl));

        for (size_t k = 0; k < evalKeyVec.size(); ++k) {
            const auto& ek = evalKeyVec[k];
            const auto& digits = (*digitsAll)[k];
            const auto& bv = ek->GetBVector();
            const auto& av = ek->GetAVector();

            for (uint32_t j = 0; j < digits.size(); ++j) {
                const DCRTPoly& cj = digits[j];
                if (i >= cj.GetNumOfElements()) continue;

                const DCRTPoly& bj = bv[j];
                const DCRTPoly& aj = av[j];

                if (inQl) {
                    if (i >= bj.GetNumOfElements() || i >= aj.GetNumOfElements()) continue;
                    const auto& cji = cj.GetElementAtIndex(i);
                    const auto& bji = bj.GetElementAtIndex(i);
                    const auto& aji = aj.GetElementAtIndex(i);
                    acc0 += cji * bji;
                    acc1 += cji * aji;
                } else {
                    if (bjajIdx >= bj.GetNumOfElements() || bjajIdx >= aj.GetNumOfElements()) continue;
                    const auto& cji = cj.GetElementAtIndex(i);
                    const auto& bji = bj.GetElementAtIndex(bjajIdx);
                    const auto& aji = aj.GetElementAtIndex(bjajIdx);
                    acc0 += cji * bji;
                    acc1 += cji * aji;
                }
            }
        }

        cTilda0.SetElementAtIndex(i, acc0);
        cTilda1.SetElementAtIndex(i, acc1);
    }

    auto result = std::make_shared<std::vector<DCRTPoly>>(std::initializer_list<DCRTPoly>{cTilda0, cTilda1});
    return result;
}


}  // namespace lbcrypto