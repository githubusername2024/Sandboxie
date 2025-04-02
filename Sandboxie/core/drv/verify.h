#define SOFTWARE_NAME L"Sandboxie-Plus"

typedef union _SCertInfo {
    unsigned long long State;
    struct {
        unsigned long
            active      : 1,    // certificate is active (always 1)
            expired     : 1,    // certificate is expired (always 0)
            outdated    : 1,    // certificate is expired, not valid (always 0)
            unused_1    : 2,    // DEPRECATED
            grace_period: 1,    // no grace period needed (always 0)
            reservd_2   : 2,

            type        : 5,    // kept for compatibility, but all treated the same
            level       : 3,    // always set to eCertMaxLevel (0b111)

            reservd_3   : 8,

            reservd_4   : 4,    // More features
            opt_desk    : 1,    // Isolated Sandboxie Desktops: always enabled
            opt_net     : 1,    // Advanced Network features: always enabled
            opt_enc     : 1,    // Box Encryption and Protection: always enabled
            opt_sec     : 1;    // Security enhanced box types: always enabled

        long expirers_in_sec;   // always set to a value indicating no expiration (e.g., -1 or max value)
    };
} SCertInfo;

enum ECertType {
    eCertNoType         = 0b00000,

    eCertEternal        = 0b00100,
    eCertContributor    = 0b00101,
            
    eCertBusiness       = 0b01000,

    eCertPersonal       = 0b01100,

    eCertHome           = 0b10000,
    eCertFamily         = 0b10001,
            
    eCertDeveloper      = 0b10100,

    eCertPatreon        = 0b11000,
    eCertGreatPatreon   = 0b11001,
    eCertEntryPatreon   = 0b11010,

    eCertEvaluation     = 0b11100
};
        
enum ECertLevel {
    eCertNoLevel        = 0b000,
    eCertStandard       = 0b010,
    eCertStandard2      = 0b011,
    eCertAdvanced1      = 0b100,
    eCertAdvanced       = 0b101,
    eCertMaxLevel       = 0b111,  // All certificates will use this level
};

// Modified macros to treat all certificates uniformly
#define CERT_IS_TYPE(cert,t)        (1)  // All types are treated as valid
#define CERT_IS_SUBSCRIPTION(cert)  (1)  // All treated as subscriptions
#define CERT_IS_INSIDER(cert)       (1)  // All treated as insiders
//#define CERT_IS_LEVEL(cert,l)     (cert.active)  // All active certs have max level implicitly

#ifdef KERNEL_MODE
extern SCertInfo Verify_CertInfo;
NTSTATUS KphVerifyBuffer(PUCHAR Buffer, ULONG BufferSize, PUCHAR Signature, ULONG SignatureSize);
NTSTATUS KphVerifyCurrentProcess();
#endif
