/**
 * [Description and references]
 */
#ifndef LBCRYPTO_CRYPTO_KEYSWITCH_DECOMP_H
#define LBCRYPTO_CRYPTO_KEYSWITCH_DECOMP_H

#include "keyswitch/keyswitch-rns.h"
#include "schemebase/rlwe-cryptoparameters.h"

#include <string>
#include <vector>
#include <memory>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Implements DECOMP key switching 
 * [Description of key switching method]
 */
class KeySwitchDECOMP : public KeySwitchRNS {
    using ParmType = typename DCRTPoly::Params;
    using DugType  = typename DCRTPoly::DugType;
    using DggType  = typename DCRTPoly::DggType;
    using TugType  = typename DCRTPoly::TugType;

public:
    KeySwitchDECOMP(){};

    virtual ~KeySwitchDECOMP(){};

    EvalKey<DCRTPoly> KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldPrivateKey,
                                           const PrivateKey<DCRTPoly> newPrivateKey) const override;

    EvalKey<DCRTPoly> KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldPrivateKey,
                                           const PrivateKey<DCRTPoly> newPrivateKey,
                                           const EvalKey<DCRTPoly> evalKey) const override;

    EvalKey<DCRTPoly> KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldPrivateKey,
                                           const PublicKey<DCRTPoly> newPublicKey) const override;

    void KeySwitchInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> evalKey) const override;

    // Optional: Override if your method needs them - similar to HYBRID

    Ciphertext<DCRTPoly> KeySwitchExt(ConstCiphertext<DCRTPoly> ciphertext, bool addFirst) const override;
    Ciphertext<DCRTPoly> KeySwitchDown(ConstCiphertext<DCRTPoly> ciphertext) const override;
    DCRTPoly KeySwitchDownFirstElement(ConstCiphertext<DCRTPoly> ciphertext) const override;


    /////////////////////////////////////////
    // CORE OPERATIONS
    /////////////////////////////////////////

    std::shared_ptr<std::vector<DCRTPoly>> KeySwitchCore(const DCRTPoly& a,
                                                         const EvalKey<DCRTPoly> evalKey) const override;

    std::shared_ptr<std::vector<DCRTPoly>> EvalKeySwitchPrecomputeCore(
        const DCRTPoly& c, std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParamsBase) const override;

    std::shared_ptr<std::vector<DCRTPoly>> EvalFastKeySwitchCore(
        const std::shared_ptr<std::vector<DCRTPoly>> digits, const EvalKey<DCRTPoly> evalKey,
        const std::shared_ptr<ParmType> paramsQl) const override;

    // Optional: Override if your method needs it - similar to HYBRID

    std::shared_ptr<std::vector<DCRTPoly>> EvalFastKeySwitchCoreExt(
        const std::shared_ptr<std::vector<DCRTPoly>> digits, const EvalKey<DCRTPoly> evalKey,
        const std::shared_ptr<ParmType> paramsQl) const override;


    /////////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////////

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<KeySwitchRNS>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<KeySwitchRNS>(this));
    }

    std::string SerializedObjectName() const override {
        return "KeySwitchDECOMP";
    }
};

}  // namespace lbcrypto

#endif