/* DO NOT EDIT THIS FILE - it is machine generated */
#include <native.h>

#ifndef _Included_java_lang_ThreadGroup
#define _Included_java_lang_ThreadGroup

#ifdef __cplusplus
extern "C" {
#endif

/* Header for class java_lang_ThreadGroup */

typedef struct Hjava_lang_ThreadGroup {
  /* Fields from java/lang/Object: */
  Hjava_lang_Object base;

  /* Fields from java/lang/ThreadGroup: */
  struct Hjava_lang_ThreadGroup* parent;
  struct Hjava_lang_String* name;
  struct Hjava_util_Vector* threads;
  struct Hjava_util_Vector* groups;
  jboolean daemon_flag;
  jint maxpri;
} Hjava_lang_ThreadGroup;


#ifdef __cplusplus
}
#endif

#endif
