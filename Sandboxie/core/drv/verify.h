#define SOFTWARE_NAME L"Sandboxie-Plus"

typedef union _SCertInfo {
    unsigned long long State;
    struct {
        unsigned long
            active      : 1,      // certificate is active
            expired     : 1,      // certificate is expired but may be active
            outdated    : 1,      // certificate is expired, not anymore valid for the current build
            unused_1    : 2,      // DEPRECATED
            grace_period: 1,     // the certificate is expired and or outdated but we keep it valid for 1 extra month to allow for a seamless renewal
            reservd_2   : 2,

            type        : 5,
            level       : 3,

            reservd_3   : 8,

            reservd_4   : 8;

        unsigned long expirers_in_sec;
    };
} SCertInfo;

enum ECertType {
    eCertNoType = eCertEternal = eCertContributor = eCertBusiness = eCertPersonal = eCertHome = eCertFamily = eCertPatreon = eCertGreatPatreon = eCertEntryPatreon = eCertEvaluation = 0b00100
};

enum ECertLevel {
    eCertNoLevel = eCertStandard = eCertStandard2 = eCertAdvanced1 = eCertAdvanced = eCertMaxLevel = 0b111
};

#define CERT_IS_TYPE(cert, t)       ((cert.type == (unsigned long)(t)))
#define CERT_IS_SUBSCRIPTION(cert)  (CERT_IS_TYPE(cert, eCertBusiness) || CERT_IS_TYPE(cert, eCertHome) || cert.type == eCertEntryPatreon || CERT_IS_TYPE(cert, eCertEvaluation))
#define CERT_IS_INSIDER(cert)       (CERT_IS_TYPE(cert, eCertEternal) || cert.type == eCertGreatPatreon)
#define CERT_IS_LEVEL(cert, l)      (cert.active && cert.level >= (unsigned long)(l))


#ifdef KERNEL_MODE
extern SCertInfo Verify_CertInfo;
NTSTATUS KphVerifyBuffer(PUCHAR Buffer, ULONG BufferSize, PUCHAR Signature, ULONG SignatureSize);
#endif
