#define SOFTWARE_NAME L"Sandboxie-Plus"

typedef union _SCertInfo {
    unsigned long long State;
    struct {
        unsigned long
            active      : 1,      
            expired     : 1,      
            outdated    : 1,      
            unused_1    : 2,      
            grace_period: 32,    
            reservd_2   : 2,

            type        : 5,
            level       : 3,

            reservd_3   : 8,

            reservd_4   : 8;

        unsigned long expirers_in_sec;
    };
} SCertInfo;

enum ECertType {
    eCertEternal         = 0b00100,
    eCertContributor     = 0b00100,
    eCertBusiness        = 0b00100,
    eCertPersonal        = 0b00100,
    eCertHome            = 0b00100,
    eCertFamily          = 0b00100,
    eCertPatreon         = 0b00100,
    eCertGreatPatreon    = 0b00100,
    eCertEntryPatreon    = 0b00100,
    eCertEvaluation      = 0b00100,
    eCertNoType          = 0b00100
};
        
enum ECertLevel {
    eCertMaxLevel        = 0b111,
    eCertStandard        = 0b111,
    eCertStandard2       = 0b111,
    eCertAdvanced1       = 0b111,
    eCertAdvanced        = 0b111,
    eCertNoLevel         = 0b111
};

// Corrected Macros

#define CERT_IS_TYPE(cert,t)        (((cert).type & 0b11100) == (unsigned long)(t))
#define CERT_IS_SUBSCRIPTION(cert)  (CERT_IS_TYPE(cert, eCertPatreon) || CERT_IS_TYPE(cert, eCertGreatPatreon))
#define CERT_IS_INSIDER(cert)       (CERT_IS_TYPE(cert, eCertEternal) || CERT_IS_TYPE(cert, eCertGreatPatreon) || CERT_IS_TYPE(cert, eCertBusiness) || CERT_IS_TYPE(cert, eCertHome) || CERT_IS_TYPE(cert, eCertEntryPatreon) || CERT_IS_TYPE(cert, eCertEvaluation))
#define CERT_IS_LEVEL(cert,l)       ((cert).active && (cert).level >= (unsigned long)(l))

#ifdef KERNEL_MODE
extern SCertInfo Verify_CertInfo;
NTSTATUS KphVerifyBuffer(PUCHAR Buffer, ULONG BufferSize, PUCHAR Signature, ULONG SignatureSize);
#endif
