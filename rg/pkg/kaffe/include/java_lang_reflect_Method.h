/* DO NOT EDIT THIS FILE - it is machine generated */
#include <native.h>

#ifndef _Included_java_lang_reflect_Method
#define _Included_java_lang_reflect_Method

#ifdef __cplusplus
extern "C" {
#endif

/* Header for class java_lang_reflect_Method */

typedef struct Hjava_lang_reflect_Method {
  /* Fields from java/lang/Object: */
  Hjava_lang_Object base;

  /* Fields from java/lang/reflect/AccessibleObject: */
  jboolean flag;

  /* Fields from java/lang/reflect/Method: */
  struct Hjava_lang_Class* clazz;
  jint slot;
  struct Hjava_lang_String* name;
  struct Hjava_lang_Class* returnType;
  HArrayOfObject* parameterTypes;
  HArrayOfObject* exceptionTypes;
} Hjava_lang_reflect_Method;

extern void java_lang_reflect_Method_init0(void);
extern jint java_lang_reflect_Method_getModifiers(struct Hjava_lang_reflect_Method*);
extern struct Hjava_lang_Object* java_lang_reflect_Method_invoke0(struct Hjava_lang_reflect_Method*, struct Hjava_lang_Object*, HArrayOfObject*);

#ifdef __cplusplus
}
#endif

#endif
