#include <openssl/x509.h>

/* Method prototypes */
time_t getTimeFromASN1(const ASN1_TIME * aTime);