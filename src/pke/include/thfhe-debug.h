#ifndef THFHE_DEBUG_H
#define THFHE_DEBUG_H

#include <iostream>
#include <iomanip>
#include <cmath>

namespace lbcrypto {

// Global debug flags
inline bool g_thfhe_debug = false;      // Enable debug output
inline bool g_thfhe_zeroA = false;      // Use a=0 in KeyGen for error tracking
inline double g_thfhe_logQ = 0.0;       // Cache log2(Q) for margin calculation

// Helper: compute log2 of infinity norm
inline double DebugLogNorm(const DCRTPoly& poly) {
    DCRTPoly p = poly;
    p.SetFormat(Format::COEFFICIENT);
    double norm = p.Norm();
    return (norm > 0) ? std::log2(norm) : 0.0;
}

// Helper: print first few coefficients for debugging
inline void DebugPrintCoeffs(const std::string& label, const DCRTPoly& poly, size_t count = 8) {
    if (!g_thfhe_debug) return;
    DCRTPoly p = poly;
    p.SetFormat(Format::COEFFICIENT);

    std::cout << "[DEBUG] " << label << " first " << count << " coeffs (tower 0): ";
    if (p.GetNumOfElements() > 0) {
        const auto& tower0 = p.GetElementAtIndex(0);
        auto len = std::min(count, (size_t)tower0.GetLength());
        for (size_t i = 0; i < len; ++i) {
            std::cout << tower0[i] << " ";
        }
    }
    std::cout << std::endl;
}

// Helper: compute log2(Q) from params
inline double DebugComputeLogQ(const std::shared_ptr<ILDCRTParams<BigInteger>>& params) {
    double sumBits = 0.0;
    for (size_t k = 0; k < params->GetParams().size(); ++k) {
        sumBits += params->GetParams()[k]->GetModulus().GetMSB();
    }
    return sumBits;
}

// Helper: print polynomial stats with correct margin
// For BFV with plaintextModulus=2: noise < Q/4 for correct decryption
// margin = log2(Q/4) - log2(norm) = logQ - 2 - logNorm
inline void DebugPrintNorm(const std::string& label, const DCRTPoly& poly) {
    if (!g_thfhe_debug) return;
    double logNorm = DebugLogNorm(poly);
    double logBound = g_thfhe_logQ - 2.0;  // log2(Q/4) for plaintextMod=2
    double margin = logBound - logNorm;

    std::cout << "[DEBUG] " << std::setw(30) << std::left << label
              << ": log2(norm) = " << std::fixed << std::setprecision(2)
              << std::setw(8) << logNorm << " bits";

    if (g_thfhe_logQ > 0) {
        std::cout << ", margin = " << std::setw(8) << margin << " bits";
        if (margin < 0) {
            std::cout << " [OVERFLOW!]";
        } else if (margin < 10) {
            std::cout << " [WARNING]";
        }
    }
    std::cout << std::endl;
}

}  // namespace lbcrypto

#endif  // THFHE_DEBUG_H
