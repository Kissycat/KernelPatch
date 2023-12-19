#ifndef _KPU_KPATCH_H_
#define _KPU_KPATCH_H_

#include <stdint.h>
#include <unistd.h>
#include "../version"

#ifdef __cplusplus
extern "C"
{
#endif

    uint32_t version();

    uint32_t hello(const char *key);
    uint32_t kpv(const char *key);

    int __test(const char *key);

    int android_user_init(const char *key);

#ifdef __cplusplus
}
#endif

#endif