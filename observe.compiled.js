📦
180394 /observe.js
✄
// node_modules/frida-objc-bridge/lib/api.js
var cachedApi = null;
var defaultInvocationOptions = {
  exceptions: "propagate"
};
function getApi() {
  if (cachedApi !== null) {
    return cachedApi;
  }
  const temporaryApi = {};
  const pending = [
    {
      module: "libsystem_malloc.dylib",
      functions: {
        "free": ["void", ["pointer"]]
      }
    },
    {
      module: "libobjc.A.dylib",
      functions: {
        "objc_msgSend": function(address) {
          this.objc_msgSend = address;
        },
        "objc_msgSend_stret": function(address) {
          this.objc_msgSend_stret = address;
        },
        "objc_msgSend_fpret": function(address) {
          this.objc_msgSend_fpret = address;
        },
        "objc_msgSendSuper": function(address) {
          this.objc_msgSendSuper = address;
        },
        "objc_msgSendSuper_stret": function(address) {
          this.objc_msgSendSuper_stret = address;
        },
        "objc_msgSendSuper_fpret": function(address) {
          this.objc_msgSendSuper_fpret = address;
        },
        "objc_getClassList": ["int", ["pointer", "int"]],
        "objc_lookUpClass": ["pointer", ["pointer"]],
        "objc_allocateClassPair": ["pointer", ["pointer", "pointer", "pointer"]],
        "objc_disposeClassPair": ["void", ["pointer"]],
        "objc_registerClassPair": ["void", ["pointer"]],
        "class_isMetaClass": ["bool", ["pointer"]],
        "class_getName": ["pointer", ["pointer"]],
        "class_getImageName": ["pointer", ["pointer"]],
        "class_copyProtocolList": ["pointer", ["pointer", "pointer"]],
        "class_copyMethodList": ["pointer", ["pointer", "pointer"]],
        "class_getClassMethod": ["pointer", ["pointer", "pointer"]],
        "class_getInstanceMethod": ["pointer", ["pointer", "pointer"]],
        "class_getSuperclass": ["pointer", ["pointer"]],
        "class_addProtocol": ["bool", ["pointer", "pointer"]],
        "class_addMethod": ["bool", ["pointer", "pointer", "pointer", "pointer"]],
        "class_copyIvarList": ["pointer", ["pointer", "pointer"]],
        "objc_getProtocol": ["pointer", ["pointer"]],
        "objc_copyProtocolList": ["pointer", ["pointer"]],
        "objc_allocateProtocol": ["pointer", ["pointer"]],
        "objc_registerProtocol": ["void", ["pointer"]],
        "protocol_getName": ["pointer", ["pointer"]],
        "protocol_copyMethodDescriptionList": ["pointer", ["pointer", "bool", "bool", "pointer"]],
        "protocol_copyPropertyList": ["pointer", ["pointer", "pointer"]],
        "protocol_copyProtocolList": ["pointer", ["pointer", "pointer"]],
        "protocol_addProtocol": ["void", ["pointer", "pointer"]],
        "protocol_addMethodDescription": ["void", ["pointer", "pointer", "pointer", "bool", "bool"]],
        "ivar_getName": ["pointer", ["pointer"]],
        "ivar_getTypeEncoding": ["pointer", ["pointer"]],
        "ivar_getOffset": ["pointer", ["pointer"]],
        "object_isClass": ["bool", ["pointer"]],
        "object_getClass": ["pointer", ["pointer"]],
        "object_getClassName": ["pointer", ["pointer"]],
        "method_getName": ["pointer", ["pointer"]],
        "method_getTypeEncoding": ["pointer", ["pointer"]],
        "method_getImplementation": ["pointer", ["pointer"]],
        "method_setImplementation": ["pointer", ["pointer", "pointer"]],
        "property_getName": ["pointer", ["pointer"]],
        "property_copyAttributeList": ["pointer", ["pointer", "pointer"]],
        "sel_getName": ["pointer", ["pointer"]],
        "sel_registerName": ["pointer", ["pointer"]],
        "class_getInstanceSize": ["pointer", ["pointer"]]
      },
      optionals: {
        "objc_msgSend_stret": "ABI",
        "objc_msgSend_fpret": "ABI",
        "objc_msgSendSuper_stret": "ABI",
        "objc_msgSendSuper_fpret": "ABI",
        "object_isClass": "iOS8"
      }
    },
    {
      module: "libdispatch.dylib",
      functions: {
        "dispatch_async_f": ["void", ["pointer", "pointer", "pointer"]]
      },
      variables: {
        "_dispatch_main_q": function(address) {
          this._dispatch_main_q = address;
        }
      }
    }
  ];
  let remaining = 0;
  pending.forEach(function(api2) {
    const functions = api2.functions || {};
    const variables = api2.variables || {};
    const optionals = api2.optionals || {};
    remaining += Object.keys(functions).length + Object.keys(variables).length;
    const exportByName = (Process.findModuleByName(api2.module)?.enumerateExports() ?? []).reduce(function(result, exp) {
      result[exp.name] = exp;
      return result;
    }, {});
    Object.keys(functions).forEach(function(name) {
      const exp = exportByName[name];
      if (exp !== void 0 && exp.type === "function") {
        const signature2 = functions[name];
        if (typeof signature2 === "function") {
          signature2.call(temporaryApi, exp.address);
        } else {
          temporaryApi[name] = new NativeFunction(exp.address, signature2[0], signature2[1], defaultInvocationOptions);
        }
        remaining--;
      } else {
        const optional = optionals[name];
        if (optional)
          remaining--;
      }
    });
    Object.keys(variables).forEach(function(name) {
      const exp = exportByName[name];
      if (exp !== void 0 && exp.type === "variable") {
        const handler = variables[name];
        handler.call(temporaryApi, exp.address);
        remaining--;
      }
    });
  });
  if (remaining === 0) {
    if (!temporaryApi.objc_msgSend_stret)
      temporaryApi.objc_msgSend_stret = temporaryApi.objc_msgSend;
    if (!temporaryApi.objc_msgSend_fpret)
      temporaryApi.objc_msgSend_fpret = temporaryApi.objc_msgSend;
    if (!temporaryApi.objc_msgSendSuper_stret)
      temporaryApi.objc_msgSendSuper_stret = temporaryApi.objc_msgSendSuper;
    if (!temporaryApi.objc_msgSendSuper_fpret)
      temporaryApi.objc_msgSendSuper_fpret = temporaryApi.objc_msgSendSuper;
    cachedApi = temporaryApi;
  }
  return cachedApi;
}

// node_modules/frida-objc-bridge/lib/fastpaths.js
var code = `#include <glib.h>
#include <ptrauth.h>

#define KERN_SUCCESS 0
#define MALLOC_PTR_IN_USE_RANGE_TYPE 1
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
# define OBJC_ISA_MASK 0x7ffffffffff8ULL
#elif defined (HAVE_ARM64)
# define OBJC_ISA_MASK 0xffffffff8ULL
#endif

typedef struct _ChooseContext ChooseContext;

typedef struct _malloc_zone_t malloc_zone_t;
typedef struct _malloc_introspection_t malloc_introspection_t;
typedef struct _vm_range_t vm_range_t;

typedef gpointer Class;
typedef int kern_return_t;
typedef guint mach_port_t;
typedef mach_port_t task_t;
typedef guintptr vm_offset_t;
typedef guintptr vm_size_t;
typedef vm_offset_t vm_address_t;

struct _ChooseContext
{
  GHashTable * classes;
  GArray * matches;
};

struct _malloc_zone_t
{
  void * reserved1;
  void * reserved2;
  size_t (* size) (struct _malloc_zone_t * zone, const void * ptr);
  void * (* malloc) (struct _malloc_zone_t * zone, size_t size);
  void * (* calloc) (struct _malloc_zone_t * zone, size_t num_items, size_t size);
  void * (* valloc) (struct _malloc_zone_t * zone, size_t size);
  void (* free) (struct _malloc_zone_t * zone, void * ptr);
  void * (* realloc) (struct _malloc_zone_t * zone, void * ptr, size_t size);
  void (* destroy) (struct _malloc_zone_t * zone);
  const char * zone_name;

  unsigned (* batch_malloc) (struct _malloc_zone_t * zone, size_t size, void ** results, unsigned num_requested);
  void (* batch_free) (struct _malloc_zone_t * zone, void ** to_be_freed, unsigned num_to_be_freed);

  malloc_introspection_t * introspect;
};

typedef kern_return_t (* memory_reader_t) (task_t remote_task, vm_address_t remote_address, vm_size_t size, void ** local_memory);
typedef void (* vm_range_recorder_t) (task_t task, void * user_data, unsigned type, vm_range_t * ranges, unsigned count);
typedef kern_return_t (* enumerator_func) (task_t task, void * user_data, unsigned type_mask, vm_address_t zone_address, memory_reader_t reader,
      vm_range_recorder_t recorder);

struct _malloc_introspection_t
{
  enumerator_func enumerator;
};

struct _vm_range_t
{
  vm_address_t address;
  vm_size_t size;
};

extern int objc_getClassList (Class * buffer, int buffer_count);
extern Class class_getSuperclass (Class cls);
extern size_t class_getInstanceSize (Class cls);
extern kern_return_t malloc_get_all_zones (task_t task, memory_reader_t reader, vm_address_t ** addresses, unsigned * count);

static void collect_subclasses (Class klass, GHashTable * result);
static void collect_matches_in_ranges (task_t task, void * user_data, unsigned type, vm_range_t * ranges, unsigned count);
static kern_return_t read_local_memory (task_t remote_task, vm_address_t remote_address, vm_size_t size, void ** local_memory);

extern mach_port_t selfTask;

gpointer *
choose (Class * klass,
        gboolean consider_subclasses,
        guint * count)
{
  ChooseContext ctx;
  GHashTable * classes;
  vm_address_t * malloc_zone_addresses;
  unsigned malloc_zone_count, i;

  classes = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  ctx.classes = classes;
  ctx.matches = g_array_new (FALSE, FALSE, sizeof (gpointer));
  if (consider_subclasses)
    collect_subclasses (klass, classes);
  else
    g_hash_table_insert (classes, klass, GSIZE_TO_POINTER (class_getInstanceSize (klass)));

  malloc_zone_count = 0;
  malloc_get_all_zones (selfTask, read_local_memory, &malloc_zone_addresses, &malloc_zone_count);

  for (i = 0; i != malloc_zone_count; i++)
  {
    vm_address_t zone_address = malloc_zone_addresses[i];
    malloc_zone_t * zone = (malloc_zone_t *) zone_address;
    enumerator_func enumerator;

    if (zone != NULL && zone->introspect != NULL &&
        (enumerator = (ptrauth_strip (zone->introspect, ptrauth_key_asda))->enumerator) != NULL)
    {
      enumerator = ptrauth_sign_unauthenticated (
          ptrauth_strip (enumerator, ptrauth_key_asia),
          ptrauth_key_asia, 0);

      enumerator (selfTask, &ctx, MALLOC_PTR_IN_USE_RANGE_TYPE, zone_address, read_local_memory,
          collect_matches_in_ranges);
    }
  }

  g_hash_table_unref (classes);

  *count = ctx.matches->len;

  return (gpointer *) g_array_free (ctx.matches, FALSE);
}

void
destroy (gpointer mem)
{
  g_free (mem);
}

static void
collect_subclasses (Class klass,
                    GHashTable * result)
{
  Class * classes;
  int buffer_count, count, i;

  buffer_count = objc_getClassList (NULL, 0);
  classes = g_malloc (buffer_count * sizeof (gpointer));
  count = objc_getClassList (classes, buffer_count);
  if (count > buffer_count)
    count = buffer_count;

  for (i = 0; i != count; i++)
  {
    Class candidate = classes[i];
    Class c;

    c = candidate;
    do
    {
      if (c == klass)
      {
        g_hash_table_insert (result, candidate, GSIZE_TO_POINTER (class_getInstanceSize (candidate)));
        break;
      }

      c = class_getSuperclass (c);
    }
    while (c != NULL);
  }

  g_free (classes);
}

static void
collect_matches_in_ranges (task_t task,
                           void * user_data,
                           unsigned type,
                           vm_range_t * ranges,
                           unsigned count)
{
  ChooseContext * ctx = user_data;
  GHashTable * classes = ctx->classes;
  unsigned i;

  for (i = 0; i != count; i++)
  {
    const vm_range_t * range = &ranges[i];
    gconstpointer candidate = GSIZE_TO_POINTER (range->address);
    gconstpointer isa;
    guint instance_size;

    isa = *(gconstpointer *) candidate;
#ifdef OBJC_ISA_MASK
    isa = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (isa) & OBJC_ISA_MASK);
#endif

    instance_size = GPOINTER_TO_UINT (g_hash_table_lookup (classes, isa));
    if (instance_size != 0 && range->size >= instance_size)
    {
      g_array_append_val (ctx->matches, candidate);
    }
  }
}

static kern_return_t
read_local_memory (task_t remote_task,
                   vm_address_t remote_address,
                   vm_size_t size,
                   void ** local_memory)
{
  *local_memory = (void *) remote_address;

  return KERN_SUCCESS;
}
`;
var { pointerSize: pointerSize2 } = Process;
var cachedModule = null;
function get() {
  if (cachedModule === null)
    cachedModule = compileModule();
  return cachedModule;
}
function compileModule() {
  const {
    objc_getClassList,
    class_getSuperclass,
    class_getInstanceSize
  } = getApi();
  const selfTask = Memory.alloc(4);
  selfTask.writeU32(Module.getGlobalExportByName("mach_task_self_").readU32());
  const cm = new CModule(code, {
    objc_getClassList,
    class_getSuperclass,
    class_getInstanceSize,
    malloc_get_all_zones: Process.getModuleByName("/usr/lib/system/libsystem_malloc.dylib").getExportByName("malloc_get_all_zones"),
    selfTask
  });
  const _choose = new NativeFunction(cm.choose, "pointer", ["pointer", "bool", "pointer"]);
  const _destroy = new NativeFunction(cm.destroy, "void", ["pointer"]);
  return {
    handle: cm,
    choose(klass, considerSubclasses) {
      const result = [];
      const countPtr = Memory.alloc(4);
      const matches = _choose(klass, considerSubclasses ? 1 : 0, countPtr);
      try {
        const count = countPtr.readU32();
        for (let i = 0; i !== count; i++)
          result.push(matches.add(i * pointerSize2).readPointer());
      } finally {
        _destroy(matches);
      }
      return result;
    }
  };
}

// node_modules/frida-objc-bridge/index.js
function Runtime() {
  const pointerSize = Process.pointerSize;
  let api = null;
  let apiError = null;
  const realizedClasses = /* @__PURE__ */ new Set();
  const classRegistry = new ClassRegistry();
  const protocolRegistry = new ProtocolRegistry();
  const replacedMethods = /* @__PURE__ */ new Map();
  const scheduledWork = /* @__PURE__ */ new Map();
  let nextId = 1;
  let workCallback = null;
  let NSAutoreleasePool = null;
  const bindings = /* @__PURE__ */ new Map();
  let readObjectIsa = null;
  const msgSendBySignatureId = /* @__PURE__ */ new Map();
  const msgSendSuperBySignatureId = /* @__PURE__ */ new Map();
  let cachedNSString = null;
  let cachedNSStringCtor = null;
  let cachedNSNumber = null;
  let cachedNSNumberCtor = null;
  let singularTypeById = null;
  let modifiers = null;
  try {
    tryInitialize();
  } catch (e) {
  }
  function tryInitialize() {
    if (api !== null)
      return true;
    if (apiError !== null)
      throw apiError;
    try {
      api = getApi();
    } catch (e) {
      apiError = e;
      throw e;
    }
    return api !== null;
  }
  function dispose() {
    for (const [rawMethodHandle, impls] of replacedMethods.entries()) {
      const methodHandle = ptr(rawMethodHandle);
      const [oldImp, newImp] = impls;
      if (api.method_getImplementation(methodHandle).equals(newImp))
        api.method_setImplementation(methodHandle, oldImp);
    }
    replacedMethods.clear();
  }
  Script.bindWeak(this, dispose);
  Object.defineProperty(this, "available", {
    enumerable: true,
    get() {
      return tryInitialize();
    }
  });
  Object.defineProperty(this, "api", {
    enumerable: true,
    get() {
      return getApi();
    }
  });
  Object.defineProperty(this, "classes", {
    enumerable: true,
    value: classRegistry
  });
  Object.defineProperty(this, "protocols", {
    enumerable: true,
    value: protocolRegistry
  });
  Object.defineProperty(this, "Object", {
    enumerable: true,
    value: ObjCObject
  });
  Object.defineProperty(this, "Protocol", {
    enumerable: true,
    value: ObjCProtocol
  });
  Object.defineProperty(this, "Block", {
    enumerable: true,
    value: Block
  });
  Object.defineProperty(this, "mainQueue", {
    enumerable: true,
    get() {
      return api?._dispatch_main_q ?? null;
    }
  });
  Object.defineProperty(this, "registerProxy", {
    enumerable: true,
    value: registerProxy
  });
  Object.defineProperty(this, "registerClass", {
    enumerable: true,
    value: registerClass
  });
  Object.defineProperty(this, "registerProtocol", {
    enumerable: true,
    value: registerProtocol
  });
  Object.defineProperty(this, "bind", {
    enumerable: true,
    value: bind
  });
  Object.defineProperty(this, "unbind", {
    enumerable: true,
    value: unbind
  });
  Object.defineProperty(this, "getBoundData", {
    enumerable: true,
    value: getBoundData
  });
  Object.defineProperty(this, "enumerateLoadedClasses", {
    enumerable: true,
    value: enumerateLoadedClasses
  });
  Object.defineProperty(this, "enumerateLoadedClassesSync", {
    enumerable: true,
    value: enumerateLoadedClassesSync
  });
  Object.defineProperty(this, "choose", {
    enumerable: true,
    value: choose
  });
  Object.defineProperty(this, "chooseSync", {
    enumerable: true,
    value(specifier) {
      const instances = [];
      choose(specifier, {
        onMatch(i) {
          instances.push(i);
        },
        onComplete() {
        }
      });
      return instances;
    }
  });
  this.schedule = function(queue, work) {
    const id = ptr(nextId++);
    scheduledWork.set(id.toString(), work);
    if (workCallback === null) {
      workCallback = new NativeCallback(performScheduledWorkItem, "void", ["pointer"]);
    }
    Script.pin();
    api.dispatch_async_f(queue, id, workCallback);
  };
  function performScheduledWorkItem(rawId) {
    const id = rawId.toString();
    const work = scheduledWork.get(id);
    scheduledWork.delete(id);
    if (NSAutoreleasePool === null)
      NSAutoreleasePool = classRegistry.NSAutoreleasePool;
    const pool = NSAutoreleasePool.alloc().init();
    let pendingException = null;
    try {
      work();
    } catch (e) {
      pendingException = e;
    }
    pool.release();
    setImmediate(performScheduledWorkCleanup, pendingException);
  }
  function performScheduledWorkCleanup(pendingException) {
    Script.unpin();
    if (pendingException !== null) {
      throw pendingException;
    }
  }
  this.implement = function(method2, fn) {
    return new NativeCallback(fn, method2.returnType, method2.argumentTypes);
  };
  this.selector = selector;
  this.selectorAsString = selectorAsString;
  function selector(name) {
    return api.sel_registerName(Memory.allocUtf8String(name));
  }
  function selectorAsString(sel2) {
    return api.sel_getName(sel2).readCString();
  }
  const registryBuiltins = /* @__PURE__ */ new Set([
    "prototype",
    "constructor",
    "hasOwnProperty",
    "toJSON",
    "toString",
    "valueOf"
  ]);
  function ClassRegistry() {
    const cachedClasses = /* @__PURE__ */ new Map();
    let numCachedClasses = 0;
    const registry = new Proxy(this, {
      has(target, property) {
        return hasProperty(property);
      },
      get(target, property, receiver) {
        switch (property) {
          case "prototype":
            return target.prototype;
          case "constructor":
            return target.constructor;
          case "hasOwnProperty":
            return hasProperty;
          case "toJSON":
            return toJSON;
          case "toString":
            return toString;
          case "valueOf":
            return valueOf;
          default:
            const klass = findClass(property);
            return klass !== null ? klass : void 0;
        }
      },
      set(target, property, value, receiver) {
        return false;
      },
      ownKeys(target) {
        if (api === null)
          return [];
        let numClasses = api.objc_getClassList(NULL, 0);
        if (numClasses !== numCachedClasses) {
          const bufferSize = numClasses;
          const classHandles = Memory.alloc(bufferSize * pointerSize);
          numClasses = api.objc_getClassList(classHandles, bufferSize);
          if (numClasses > bufferSize)
            numClasses = bufferSize;
          for (let i = 0; i !== numClasses; i++) {
            const handle2 = classHandles.add(i * pointerSize).readPointer();
            const name = api.class_getName(handle2).readCString();
            cachedClasses.set(name, handle2);
          }
          numCachedClasses = numClasses;
        }
        return Array.from(cachedClasses.keys());
      },
      getOwnPropertyDescriptor(target, property) {
        return {
          writable: false,
          configurable: true,
          enumerable: true
        };
      }
    });
    function hasProperty(name) {
      if (registryBuiltins.has(name))
        return true;
      return findClass(name) !== null;
    }
    function getClass(name) {
      const cls = findClass(name);
      if (cls === null)
        throw new Error("Unable to find class '" + name + "'");
      return cls;
    }
    function findClass(name) {
      let handle2 = cachedClasses.get(name);
      if (handle2 === void 0) {
        handle2 = api.objc_lookUpClass(Memory.allocUtf8String(name));
        if (handle2.isNull())
          return null;
        cachedClasses.set(name, handle2);
        numCachedClasses++;
      }
      return new ObjCObject(handle2, void 0, true);
    }
    function toJSON() {
      return Object.keys(registry).reduce(function(r, name) {
        r[name] = getClass(name).toJSON();
        return r;
      }, {});
    }
    function toString() {
      return "ClassRegistry";
    }
    function valueOf() {
      return "ClassRegistry";
    }
    return registry;
  }
  function ProtocolRegistry() {
    const cachedProtocols = /* @__PURE__ */ new Map();
    let numCachedProtocols = 0;
    const registry = new Proxy(this, {
      has(target, property) {
        return hasProperty(property);
      },
      get(target, property, receiver) {
        switch (property) {
          case "prototype":
            return target.prototype;
          case "constructor":
            return target.constructor;
          case "hasOwnProperty":
            return hasProperty;
          case "toJSON":
            return toJSON;
          case "toString":
            return toString;
          case "valueOf":
            return valueOf;
          default:
            const proto = findProtocol(property);
            return proto !== null ? proto : void 0;
        }
      },
      set(target, property, value, receiver) {
        return false;
      },
      ownKeys(target) {
        if (api === null)
          return [];
        const numProtocolsBuf = Memory.alloc(pointerSize);
        const protocolHandles = api.objc_copyProtocolList(numProtocolsBuf);
        try {
          const numProtocols = numProtocolsBuf.readUInt();
          if (numProtocols !== numCachedProtocols) {
            cachedProtocols.clear();
            for (let i = 0; i !== numProtocols; i++) {
              const handle2 = protocolHandles.add(i * pointerSize).readPointer();
              const name = api.protocol_getName(handle2).readCString();
              cachedProtocols.set(name, handle2);
            }
            numCachedProtocols = numProtocols;
          }
        } finally {
          api.free(protocolHandles);
        }
        return Array.from(cachedProtocols.keys());
      },
      getOwnPropertyDescriptor(target, property) {
        return {
          writable: false,
          configurable: true,
          enumerable: true
        };
      }
    });
    function hasProperty(name) {
      if (registryBuiltins.has(name))
        return true;
      return findProtocol(name) !== null;
    }
    function findProtocol(name) {
      let handle2 = cachedProtocols.get(name);
      if (handle2 === void 0) {
        handle2 = api.objc_getProtocol(Memory.allocUtf8String(name));
        if (handle2.isNull())
          return null;
        cachedProtocols.set(name, handle2);
        numCachedProtocols++;
      }
      return new ObjCProtocol(handle2);
    }
    function toJSON() {
      return Object.keys(registry).reduce(function(r, name) {
        r[name] = { handle: cachedProtocols.get(name) };
        return r;
      }, {});
    }
    function toString() {
      return "ProtocolRegistry";
    }
    function valueOf() {
      return "ProtocolRegistry";
    }
    return registry;
  }
  const objCObjectBuiltins = /* @__PURE__ */ new Set([
    "prototype",
    "constructor",
    "handle",
    "hasOwnProperty",
    "toJSON",
    "toString",
    "valueOf",
    "equals",
    "$kind",
    "$super",
    "$superClass",
    "$class",
    "$className",
    "$moduleName",
    "$protocols",
    "$methods",
    "$ownMethods",
    "$ivars"
  ]);
  function ObjCObject(handle2, protocol, cachedIsClass, superSpecifier2) {
    let cachedClassHandle = null;
    let cachedKind = null;
    let cachedSuper = null;
    let cachedSuperClass = null;
    let cachedClass = null;
    let cachedClassName = null;
    let cachedModuleName = null;
    let cachedProtocols = null;
    let cachedMethodNames = null;
    let cachedProtocolMethods = null;
    let respondsToSelector = null;
    const cachedMethods = /* @__PURE__ */ new Map();
    let cachedNativeMethodNames = null;
    let cachedOwnMethodNames = null;
    let cachedIvars = null;
    handle2 = getHandle(handle2);
    if (cachedIsClass === void 0) {
      const klass = api.object_getClass(handle2);
      const key = klass.toString();
      if (!realizedClasses.has(key)) {
        api.objc_lookUpClass(api.class_getName(klass));
        realizedClasses.add(key);
      }
    }
    const self = new Proxy(this, {
      has(target, property) {
        return hasProperty(property);
      },
      get(target, property, receiver) {
        switch (property) {
          case "handle":
            return handle2;
          case "prototype":
            return target.prototype;
          case "constructor":
            return target.constructor;
          case "hasOwnProperty":
            return hasProperty;
          case "toJSON":
            return toJSON;
          case "toString":
          case "valueOf":
            const descriptionImpl = receiver.description;
            if (descriptionImpl !== void 0) {
              const description = descriptionImpl.call(receiver);
              if (description !== null)
                return description.UTF8String.bind(description);
            }
            return function() {
              return receiver.$className;
            };
          case "equals":
            return equals;
          case "$kind":
            if (cachedKind === null) {
              if (isClass())
                cachedKind = api.class_isMetaClass(handle2) ? "meta-class" : "class";
              else
                cachedKind = "instance";
            }
            return cachedKind;
          case "$super":
            if (cachedSuper === null) {
              const superHandle = api.class_getSuperclass(classHandle());
              if (!superHandle.isNull()) {
                const specifier = Memory.alloc(2 * pointerSize);
                specifier.writePointer(handle2);
                specifier.add(pointerSize).writePointer(superHandle);
                cachedSuper = [new ObjCObject(handle2, void 0, cachedIsClass, specifier)];
              } else {
                cachedSuper = [null];
              }
            }
            return cachedSuper[0];
          case "$superClass":
            if (cachedSuperClass === null) {
              const superClassHandle = api.class_getSuperclass(classHandle());
              if (!superClassHandle.isNull()) {
                cachedSuperClass = [new ObjCObject(superClassHandle)];
              } else {
                cachedSuperClass = [null];
              }
            }
            return cachedSuperClass[0];
          case "$class":
            if (cachedClass === null)
              cachedClass = new ObjCObject(api.object_getClass(handle2), void 0, true);
            return cachedClass;
          case "$className":
            if (cachedClassName === null) {
              if (superSpecifier2)
                cachedClassName = api.class_getName(superSpecifier2.add(pointerSize).readPointer()).readCString();
              else if (isClass())
                cachedClassName = api.class_getName(handle2).readCString();
              else
                cachedClassName = api.object_getClassName(handle2).readCString();
            }
            return cachedClassName;
          case "$moduleName":
            if (cachedModuleName === null) {
              cachedModuleName = api.class_getImageName(classHandle()).readCString();
            }
            return cachedModuleName;
          case "$protocols":
            if (cachedProtocols === null) {
              cachedProtocols = {};
              const numProtocolsBuf = Memory.alloc(pointerSize);
              const protocolHandles = api.class_copyProtocolList(classHandle(), numProtocolsBuf);
              if (!protocolHandles.isNull()) {
                try {
                  const numProtocols = numProtocolsBuf.readUInt();
                  for (let i = 0; i !== numProtocols; i++) {
                    const protocolHandle = protocolHandles.add(i * pointerSize).readPointer();
                    const p = new ObjCProtocol(protocolHandle);
                    cachedProtocols[p.name] = p;
                  }
                } finally {
                  api.free(protocolHandles);
                }
              }
            }
            return cachedProtocols;
          case "$methods":
            if (cachedNativeMethodNames === null) {
              const klass = superSpecifier2 ? superSpecifier2.add(pointerSize).readPointer() : classHandle();
              const meta = api.object_getClass(klass);
              const names = /* @__PURE__ */ new Set();
              let cur = meta;
              do {
                for (let methodName of collectMethodNames(cur, "+ "))
                  names.add(methodName);
                cur = api.class_getSuperclass(cur);
              } while (!cur.isNull());
              cur = klass;
              do {
                for (let methodName of collectMethodNames(cur, "- "))
                  names.add(methodName);
                cur = api.class_getSuperclass(cur);
              } while (!cur.isNull());
              cachedNativeMethodNames = Array.from(names);
            }
            return cachedNativeMethodNames;
          case "$ownMethods":
            if (cachedOwnMethodNames === null) {
              const klass = superSpecifier2 ? superSpecifier2.add(pointerSize).readPointer() : classHandle();
              const meta = api.object_getClass(klass);
              const classMethods = collectMethodNames(meta, "+ ");
              const instanceMethods = collectMethodNames(klass, "- ");
              cachedOwnMethodNames = classMethods.concat(instanceMethods);
            }
            return cachedOwnMethodNames;
          case "$ivars":
            if (cachedIvars === null) {
              if (isClass())
                cachedIvars = {};
              else
                cachedIvars = new ObjCIvars(self, classHandle());
            }
            return cachedIvars;
          default:
            if (typeof property === "symbol") {
              return target[property];
            }
            if (protocol) {
              const details = findProtocolMethod(property);
              if (details === null || !details.implemented)
                return void 0;
            }
            const wrapper = findMethodWrapper(property);
            if (wrapper === null)
              return void 0;
            return wrapper;
        }
      },
      set(target, property, value, receiver) {
        return false;
      },
      ownKeys(target) {
        if (cachedMethodNames === null) {
          if (!protocol) {
            const jsNames = {};
            const nativeNames = {};
            let cur = api.object_getClass(handle2);
            do {
              const numMethodsBuf = Memory.alloc(pointerSize);
              const methodHandles = api.class_copyMethodList(cur, numMethodsBuf);
              const fullNamePrefix = isClass() ? "+ " : "- ";
              try {
                const numMethods = numMethodsBuf.readUInt();
                for (let i = 0; i !== numMethods; i++) {
                  const methodHandle = methodHandles.add(i * pointerSize).readPointer();
                  const sel2 = api.method_getName(methodHandle);
                  const nativeName = api.sel_getName(sel2).readCString();
                  if (nativeNames[nativeName] !== void 0)
                    continue;
                  nativeNames[nativeName] = nativeName;
                  const jsName = jsMethodName(nativeName);
                  let serial = 2;
                  let name = jsName;
                  while (jsNames[name] !== void 0) {
                    serial++;
                    name = jsName + serial;
                  }
                  jsNames[name] = true;
                  const fullName = fullNamePrefix + nativeName;
                  if (!cachedMethods.has(fullName)) {
                    const details = {
                      sel: sel2,
                      handle: methodHandle,
                      wrapper: null
                    };
                    cachedMethods.set(fullName, details);
                    cachedMethods.set(name, details);
                  }
                }
              } finally {
                api.free(methodHandles);
              }
              cur = api.class_getSuperclass(cur);
            } while (!cur.isNull());
            cachedMethodNames = Object.keys(jsNames);
          } else {
            const methodNames = [];
            const protocolMethods = allProtocolMethods();
            Object.keys(protocolMethods).forEach(function(methodName) {
              if (methodName[0] !== "+" && methodName[0] !== "-") {
                const details = protocolMethods[methodName];
                if (details.implemented) {
                  methodNames.push(methodName);
                }
              }
            });
            cachedMethodNames = methodNames;
          }
        }
        return ["handle"].concat(cachedMethodNames);
      },
      getOwnPropertyDescriptor(target, property) {
        return {
          writable: false,
          configurable: true,
          enumerable: true
        };
      }
    });
    if (protocol) {
      respondsToSelector = !isClass() ? findMethodWrapper("- respondsToSelector:") : null;
    }
    return self;
    function hasProperty(name) {
      if (objCObjectBuiltins.has(name))
        return true;
      if (protocol) {
        const details = findProtocolMethod(name);
        return !!(details !== null && details.implemented);
      }
      return findMethod(name) !== null;
    }
    function classHandle() {
      if (cachedClassHandle === null)
        cachedClassHandle = isClass() ? handle2 : api.object_getClass(handle2);
      return cachedClassHandle;
    }
    function isClass() {
      if (cachedIsClass === void 0) {
        if (api.object_isClass)
          cachedIsClass = !!api.object_isClass(handle2);
        else
          cachedIsClass = !!api.class_isMetaClass(api.object_getClass(handle2));
      }
      return cachedIsClass;
    }
    function findMethod(rawName) {
      let method2 = cachedMethods.get(rawName);
      if (method2 !== void 0)
        return method2;
      const tokens = parseMethodName(rawName);
      const fullName = tokens[2];
      method2 = cachedMethods.get(fullName);
      if (method2 !== void 0) {
        cachedMethods.set(rawName, method2);
        return method2;
      }
      const kind = tokens[0];
      const name = tokens[1];
      const sel2 = selector(name);
      const defaultKind = isClass() ? "+" : "-";
      if (protocol) {
        const details = findProtocolMethod(fullName);
        if (details !== null) {
          method2 = {
            sel: sel2,
            types: details.types,
            wrapper: null,
            kind
          };
        }
      }
      if (method2 === void 0) {
        const methodHandle = kind === "+" ? api.class_getClassMethod(classHandle(), sel2) : api.class_getInstanceMethod(classHandle(), sel2);
        if (!methodHandle.isNull()) {
          method2 = {
            sel: sel2,
            handle: methodHandle,
            wrapper: null,
            kind
          };
        } else {
          if (isClass() || kind !== "-" || name === "forwardingTargetForSelector:" || name === "methodSignatureForSelector:") {
            return null;
          }
          let target = self;
          if ("- forwardingTargetForSelector:" in self) {
            const forwardingTarget = self.forwardingTargetForSelector_(sel2);
            if (forwardingTarget !== null && forwardingTarget.$kind === "instance") {
              target = forwardingTarget;
            } else {
              return null;
            }
          } else {
            return null;
          }
          const methodHandle2 = api.class_getInstanceMethod(api.object_getClass(target.handle), sel2);
          if (methodHandle2.isNull()) {
            return null;
          }
          let types2 = api.method_getTypeEncoding(methodHandle2).readCString();
          if (types2 === null || types2 === "") {
            types2 = stealTypesFromProtocols(target, fullName);
            if (types2 === null)
              types2 = stealTypesFromProtocols(self, fullName);
            if (types2 === null)
              return null;
          }
          method2 = {
            sel: sel2,
            types: types2,
            wrapper: null,
            kind
          };
        }
      }
      cachedMethods.set(fullName, method2);
      cachedMethods.set(rawName, method2);
      if (kind === defaultKind)
        cachedMethods.set(jsMethodName(name), method2);
      return method2;
    }
    function stealTypesFromProtocols(klass, fullName) {
      const candidates = Object.keys(klass.$protocols).map((protocolName) => flatProtocolMethods({}, klass.$protocols[protocolName])).reduce((allMethods, methods) => {
        Object.assign(allMethods, methods);
        return allMethods;
      }, {});
      const method2 = candidates[fullName];
      if (method2 === void 0) {
        return null;
      }
      return method2.types;
    }
    function flatProtocolMethods(result, protocol2) {
      if (protocol2.methods !== void 0) {
        Object.assign(result, protocol2.methods);
      }
      if (protocol2.protocol !== void 0) {
        flatProtocolMethods(result, protocol2.protocol);
      }
      return result;
    }
    function findProtocolMethod(rawName) {
      const protocolMethods = allProtocolMethods();
      const details = protocolMethods[rawName];
      return details !== void 0 ? details : null;
    }
    function allProtocolMethods() {
      if (cachedProtocolMethods === null) {
        const methods = {};
        const protocols = collectProtocols(protocol);
        const defaultKind = isClass() ? "+" : "-";
        Object.keys(protocols).forEach(function(name) {
          const p = protocols[name];
          const m2 = p.methods;
          Object.keys(m2).forEach(function(fullMethodName) {
            const method2 = m2[fullMethodName];
            const methodName = fullMethodName.substr(2);
            const kind = fullMethodName[0];
            let didCheckImplemented = false;
            let implemented = false;
            const details = {
              types: method2.types
            };
            Object.defineProperty(details, "implemented", {
              get() {
                if (!didCheckImplemented) {
                  if (method2.required) {
                    implemented = true;
                  } else {
                    implemented = respondsToSelector !== null && respondsToSelector.call(self, selector(methodName));
                  }
                  didCheckImplemented = true;
                }
                return implemented;
              }
            });
            methods[fullMethodName] = details;
            if (kind === defaultKind)
              methods[jsMethodName(methodName)] = details;
          });
        });
        cachedProtocolMethods = methods;
      }
      return cachedProtocolMethods;
    }
    function findMethodWrapper(name) {
      const method2 = findMethod(name);
      if (method2 === null)
        return null;
      let wrapper = method2.wrapper;
      if (wrapper === null) {
        wrapper = makeMethodInvocationWrapper(method2, self, superSpecifier2, defaultInvocationOptions);
        method2.wrapper = wrapper;
      }
      return wrapper;
    }
    function parseMethodName(rawName) {
      const match = /([+\-])\s(\S+)/.exec(rawName);
      let name, kind;
      if (match === null) {
        kind = isClass() ? "+" : "-";
        name = objcMethodName(rawName);
      } else {
        kind = match[1];
        name = match[2];
      }
      const fullName = [kind, name].join(" ");
      return [kind, name, fullName];
    }
    function toJSON() {
      return {
        handle: handle2.toString()
      };
    }
    function equals(ptr2) {
      return handle2.equals(getHandle(ptr2));
    }
  }
  function getReplacementMethodImplementation(methodHandle) {
    const existingEntry = replacedMethods.get(methodHandle.toString());
    if (existingEntry === void 0)
      return null;
    const [, newImp] = existingEntry;
    return newImp;
  }
  function replaceMethodImplementation(methodHandle, imp) {
    const key = methodHandle.toString();
    let oldImp;
    const existingEntry = replacedMethods.get(key);
    if (existingEntry !== void 0)
      [oldImp] = existingEntry;
    else
      oldImp = api.method_getImplementation(methodHandle);
    if (!imp.equals(oldImp))
      replacedMethods.set(key, [oldImp, imp]);
    else
      replacedMethods.delete(key);
    api.method_setImplementation(methodHandle, imp);
  }
  function collectMethodNames(klass, prefix) {
    const names = [];
    const numMethodsBuf = Memory.alloc(pointerSize);
    const methodHandles = api.class_copyMethodList(klass, numMethodsBuf);
    try {
      const numMethods = numMethodsBuf.readUInt();
      for (let i = 0; i !== numMethods; i++) {
        const methodHandle = methodHandles.add(i * pointerSize).readPointer();
        const sel2 = api.method_getName(methodHandle);
        const nativeName = api.sel_getName(sel2).readCString();
        names.push(prefix + nativeName);
      }
    } finally {
      api.free(methodHandles);
    }
    return names;
  }
  function ObjCProtocol(handle2) {
    let cachedName = null;
    let cachedProtocols = null;
    let cachedProperties = null;
    let cachedMethods = null;
    Object.defineProperty(this, "handle", {
      value: handle2,
      enumerable: true
    });
    Object.defineProperty(this, "name", {
      get() {
        if (cachedName === null)
          cachedName = api.protocol_getName(handle2).readCString();
        return cachedName;
      },
      enumerable: true
    });
    Object.defineProperty(this, "protocols", {
      get() {
        if (cachedProtocols === null) {
          cachedProtocols = {};
          const numProtocolsBuf = Memory.alloc(pointerSize);
          const protocolHandles = api.protocol_copyProtocolList(handle2, numProtocolsBuf);
          if (!protocolHandles.isNull()) {
            try {
              const numProtocols = numProtocolsBuf.readUInt();
              for (let i = 0; i !== numProtocols; i++) {
                const protocolHandle = protocolHandles.add(i * pointerSize).readPointer();
                const protocol = new ObjCProtocol(protocolHandle);
                cachedProtocols[protocol.name] = protocol;
              }
            } finally {
              api.free(protocolHandles);
            }
          }
        }
        return cachedProtocols;
      },
      enumerable: true
    });
    Object.defineProperty(this, "properties", {
      get() {
        if (cachedProperties === null) {
          cachedProperties = {};
          const numBuf = Memory.alloc(pointerSize);
          const propertyHandles = api.protocol_copyPropertyList(handle2, numBuf);
          if (!propertyHandles.isNull()) {
            try {
              const numProperties = numBuf.readUInt();
              for (let i = 0; i !== numProperties; i++) {
                const propertyHandle = propertyHandles.add(i * pointerSize).readPointer();
                const propName = api.property_getName(propertyHandle).readCString();
                const attributes = {};
                const attributeEntries = api.property_copyAttributeList(propertyHandle, numBuf);
                if (!attributeEntries.isNull()) {
                  try {
                    const numAttributeValues = numBuf.readUInt();
                    for (let j = 0; j !== numAttributeValues; j++) {
                      const attributeEntry = attributeEntries.add(j * (2 * pointerSize));
                      const name = attributeEntry.readPointer().readCString();
                      const value = attributeEntry.add(pointerSize).readPointer().readCString();
                      attributes[name] = value;
                    }
                  } finally {
                    api.free(attributeEntries);
                  }
                }
                cachedProperties[propName] = attributes;
              }
            } finally {
              api.free(propertyHandles);
            }
          }
        }
        return cachedProperties;
      },
      enumerable: true
    });
    Object.defineProperty(this, "methods", {
      get() {
        if (cachedMethods === null) {
          cachedMethods = {};
          const numBuf = Memory.alloc(pointerSize);
          collectMethods(cachedMethods, numBuf, { required: true, instance: false });
          collectMethods(cachedMethods, numBuf, { required: false, instance: false });
          collectMethods(cachedMethods, numBuf, { required: true, instance: true });
          collectMethods(cachedMethods, numBuf, { required: false, instance: true });
        }
        return cachedMethods;
      },
      enumerable: true
    });
    function collectMethods(methods, numBuf, spec) {
      const methodDescValues = api.protocol_copyMethodDescriptionList(handle2, spec.required ? 1 : 0, spec.instance ? 1 : 0, numBuf);
      if (methodDescValues.isNull())
        return;
      try {
        const numMethodDescValues = numBuf.readUInt();
        for (let i = 0; i !== numMethodDescValues; i++) {
          const methodDesc = methodDescValues.add(i * (2 * pointerSize));
          const name = (spec.instance ? "- " : "+ ") + selectorAsString(methodDesc.readPointer());
          const types2 = methodDesc.add(pointerSize).readPointer().readCString();
          methods[name] = {
            required: spec.required,
            types: types2
          };
        }
      } finally {
        api.free(methodDescValues);
      }
    }
  }
  const objCIvarsBuiltins = /* @__PURE__ */ new Set([
    "prototype",
    "constructor",
    "hasOwnProperty",
    "toJSON",
    "toString",
    "valueOf"
  ]);
  function ObjCIvars(instance, classHandle) {
    const ivars = {};
    let cachedIvarNames = null;
    let classHandles = [];
    let currentClassHandle = classHandle;
    do {
      classHandles.unshift(currentClassHandle);
      currentClassHandle = api.class_getSuperclass(currentClassHandle);
    } while (!currentClassHandle.isNull());
    const numIvarsBuf = Memory.alloc(pointerSize);
    classHandles.forEach((c) => {
      const ivarHandles = api.class_copyIvarList(c, numIvarsBuf);
      try {
        const numIvars = numIvarsBuf.readUInt();
        for (let i = 0; i !== numIvars; i++) {
          const handle2 = ivarHandles.add(i * pointerSize).readPointer();
          const name = api.ivar_getName(handle2).readCString();
          ivars[name] = [handle2, null];
        }
      } finally {
        api.free(ivarHandles);
      }
    });
    const self = new Proxy(this, {
      has(target, property) {
        return hasProperty(property);
      },
      get(target, property, receiver) {
        switch (property) {
          case "prototype":
            return target.prototype;
          case "constructor":
            return target.constructor;
          case "hasOwnProperty":
            return hasProperty;
          case "toJSON":
            return toJSON;
          case "toString":
            return toString;
          case "valueOf":
            return valueOf;
          default:
            const ivar = findIvar(property);
            if (ivar === null)
              return void 0;
            return ivar.get();
        }
      },
      set(target, property, value, receiver) {
        const ivar = findIvar(property);
        if (ivar === null)
          throw new Error("Unknown ivar");
        ivar.set(value);
        return true;
      },
      ownKeys(target) {
        if (cachedIvarNames === null)
          cachedIvarNames = Object.keys(ivars);
        return cachedIvarNames;
      },
      getOwnPropertyDescriptor(target, property) {
        return {
          writable: true,
          configurable: true,
          enumerable: true
        };
      }
    });
    return self;
    function findIvar(name) {
      const entry = ivars[name];
      if (entry === void 0)
        return null;
      let impl = entry[1];
      if (impl === null) {
        const ivar = entry[0];
        const offset = api.ivar_getOffset(ivar).toInt32();
        const address = instance.handle.add(offset);
        const type = parseType(api.ivar_getTypeEncoding(ivar).readCString());
        const fromNative = type.fromNative || identityTransform;
        const toNative = type.toNative || identityTransform;
        let read, write;
        if (name === "isa") {
          read = readObjectIsa;
          write = function() {
            throw new Error("Unable to set the isa instance variable");
          };
        } else {
          read = type.read;
          write = type.write;
        }
        impl = {
          get() {
            return fromNative.call(instance, read(address));
          },
          set(value) {
            write(address, toNative.call(instance, value));
          }
        };
        entry[1] = impl;
      }
      return impl;
    }
    function hasProperty(name) {
      if (objCIvarsBuiltins.has(name))
        return true;
      return ivars.hasOwnProperty(name);
    }
    function toJSON() {
      return Object.keys(self).reduce(function(result, name) {
        result[name] = self[name];
        return result;
      }, {});
    }
    function toString() {
      return "ObjCIvars";
    }
    function valueOf() {
      return "ObjCIvars";
    }
  }
  let blockDescriptorAllocSize, blockDescriptorDeclaredSize, blockDescriptorOffsets;
  let blockSize, blockOffsets;
  if (pointerSize === 4) {
    blockDescriptorAllocSize = 16;
    blockDescriptorDeclaredSize = 20;
    blockDescriptorOffsets = {
      reserved: 0,
      size: 4,
      rest: 8
    };
    blockSize = 20;
    blockOffsets = {
      isa: 0,
      flags: 4,
      reserved: 8,
      invoke: 12,
      descriptor: 16
    };
  } else {
    blockDescriptorAllocSize = 32;
    blockDescriptorDeclaredSize = 32;
    blockDescriptorOffsets = {
      reserved: 0,
      size: 8,
      rest: 16
    };
    blockSize = 32;
    blockOffsets = {
      isa: 0,
      flags: 8,
      reserved: 12,
      invoke: 16,
      descriptor: 24
    };
  }
  const BLOCK_HAS_COPY_DISPOSE = 1 << 25;
  const BLOCK_HAS_CTOR = 1 << 26;
  const BLOCK_IS_GLOBAL = 1 << 28;
  const BLOCK_HAS_STRET = 1 << 29;
  const BLOCK_HAS_SIGNATURE = 1 << 30;
  function Block(target, options = defaultInvocationOptions) {
    this._options = options;
    if (target instanceof NativePointer) {
      const descriptor = target.add(blockOffsets.descriptor).readPointer();
      this.handle = target;
      const flags = target.add(blockOffsets.flags).readU32();
      if ((flags & BLOCK_HAS_SIGNATURE) !== 0) {
        const signatureOffset = (flags & BLOCK_HAS_COPY_DISPOSE) !== 0 ? 2 : 0;
        this.types = descriptor.add(blockDescriptorOffsets.rest + signatureOffset * pointerSize).readPointer().readCString();
        this._signature = parseSignature(this.types);
      } else {
        this._signature = null;
      }
    } else {
      this.declare(target);
      const descriptor = Memory.alloc(blockDescriptorAllocSize + blockSize);
      const block2 = descriptor.add(blockDescriptorAllocSize);
      const typesStr = Memory.allocUtf8String(this.types);
      descriptor.add(blockDescriptorOffsets.reserved).writeULong(0);
      descriptor.add(blockDescriptorOffsets.size).writeULong(blockDescriptorDeclaredSize);
      descriptor.add(blockDescriptorOffsets.rest).writePointer(typesStr);
      block2.add(blockOffsets.isa).writePointer(classRegistry.__NSGlobalBlock__);
      block2.add(blockOffsets.flags).writeU32(BLOCK_HAS_SIGNATURE | BLOCK_IS_GLOBAL);
      block2.add(blockOffsets.reserved).writeU32(0);
      block2.add(blockOffsets.descriptor).writePointer(descriptor);
      this.handle = block2;
      this._storage = [descriptor, typesStr];
      this.implementation = target.implementation;
    }
  }
  Object.defineProperties(Block.prototype, {
    implementation: {
      enumerable: true,
      get() {
        const address = this.handle.add(blockOffsets.invoke).readPointer().strip();
        const signature2 = this._getSignature();
        return makeBlockInvocationWrapper(this, signature2, new NativeFunction(
          address.sign(),
          signature2.retType.type,
          signature2.argTypes.map(function(arg) {
            return arg.type;
          }),
          this._options
        ));
      },
      set(func) {
        const signature2 = this._getSignature();
        const callback = new NativeCallback(
          makeBlockImplementationWrapper(this, signature2, func),
          signature2.retType.type,
          signature2.argTypes.map(function(arg) {
            return arg.type;
          })
        );
        this._callback = callback;
        const location = this.handle.add(blockOffsets.invoke);
        const prot = Memory.queryProtection(location);
        const writable = prot.includes("w");
        if (!writable)
          Memory.protect(location, Process.pointerSize, "rw-");
        location.writePointer(callback.strip().sign("ia", location));
        if (!writable)
          Memory.protect(location, Process.pointerSize, prot);
      }
    },
    declare: {
      value(signature2) {
        let types2 = signature2.types;
        if (types2 === void 0) {
          types2 = unparseSignature(signature2.retType, ["block"].concat(signature2.argTypes));
        }
        this.types = types2;
        this._signature = parseSignature(types2);
      }
    },
    _getSignature: {
      value() {
        const signature2 = this._signature;
        if (signature2 === null)
          throw new Error("block is missing signature; call declare()");
        return signature2;
      }
    }
  });
  function collectProtocols(p, acc) {
    acc = acc || {};
    acc[p.name] = p;
    const parentProtocols = p.protocols;
    Object.keys(parentProtocols).forEach(function(name) {
      collectProtocols(parentProtocols[name], acc);
    });
    return acc;
  }
  function registerProxy(properties) {
    const protocols = properties.protocols || [];
    const methods = properties.methods || {};
    const events = properties.events || {};
    const supportedSelectors = new Set(
      Object.keys(methods).filter((m2) => /([+\-])\s(\S+)/.exec(m2) !== null).map((m2) => m2.split(" ")[1])
    );
    const proxyMethods = {
      "- dealloc": function() {
        const target = this.data.target;
        if ("- release" in target)
          target.release();
        unbind(this.self);
        this.super.dealloc();
        const callback = this.data.events.dealloc;
        if (callback !== void 0)
          callback.call(this);
      },
      "- respondsToSelector:": function(sel2) {
        const selector2 = selectorAsString(sel2);
        if (supportedSelectors.has(selector2))
          return true;
        return this.data.target.respondsToSelector_(sel2);
      },
      "- forwardingTargetForSelector:": function(sel2) {
        const callback = this.data.events.forward;
        if (callback !== void 0)
          callback.call(this, selectorAsString(sel2));
        return this.data.target;
      },
      "- methodSignatureForSelector:": function(sel2) {
        return this.data.target.methodSignatureForSelector_(sel2);
      },
      "- forwardInvocation:": function(invocation) {
        invocation.invokeWithTarget_(this.data.target);
      }
    };
    for (var key in methods) {
      if (methods.hasOwnProperty(key)) {
        if (proxyMethods.hasOwnProperty(key))
          throw new Error("The '" + key + "' method is reserved");
        proxyMethods[key] = methods[key];
      }
    }
    const ProxyClass = registerClass({
      name: properties.name,
      super: classRegistry.NSProxy,
      protocols,
      methods: proxyMethods
    });
    return function(target, data) {
      target = target instanceof NativePointer ? new ObjCObject(target) : target;
      data = data || {};
      const instance = ProxyClass.alloc().autorelease();
      const boundData = getBoundData(instance);
      boundData.target = "- retain" in target ? target.retain() : target;
      boundData.events = events;
      for (var key2 in data) {
        if (data.hasOwnProperty(key2)) {
          if (boundData.hasOwnProperty(key2))
            throw new Error("The '" + key2 + "' property is reserved");
          boundData[key2] = data[key2];
        }
      }
      this.handle = instance.handle;
    };
  }
  function registerClass(properties) {
    let name = properties.name;
    if (name === void 0)
      name = makeClassName();
    const superClass = properties.super !== void 0 ? properties.super : classRegistry.NSObject;
    const protocols = properties.protocols || [];
    const methods = properties.methods || {};
    const methodCallbacks = [];
    const classHandle = api.objc_allocateClassPair(superClass !== null ? superClass.handle : NULL, Memory.allocUtf8String(name), ptr("0"));
    if (classHandle.isNull())
      throw new Error("Unable to register already registered class '" + name + "'");
    const metaClassHandle = api.object_getClass(classHandle);
    try {
      protocols.forEach(function(protocol) {
        api.class_addProtocol(classHandle, protocol.handle);
      });
      Object.keys(methods).forEach(function(rawMethodName) {
        const match = /([+\-])\s(\S+)/.exec(rawMethodName);
        if (match === null)
          throw new Error("Invalid method name");
        const kind = match[1];
        const name2 = match[2];
        let method2;
        const value = methods[rawMethodName];
        if (typeof value === "function") {
          let types3 = null;
          if (rawMethodName in superClass) {
            types3 = superClass[rawMethodName].types;
          } else {
            for (let protocol of protocols) {
              const method3 = protocol.methods[rawMethodName];
              if (method3 !== void 0) {
                types3 = method3.types;
                break;
              }
            }
          }
          if (types3 === null)
            throw new Error("Unable to find '" + rawMethodName + "' in super-class or any of its protocols");
          method2 = {
            types: types3,
            implementation: value
          };
        } else {
          method2 = value;
        }
        const target = kind === "+" ? metaClassHandle : classHandle;
        let types2 = method2.types;
        if (types2 === void 0) {
          types2 = unparseSignature(method2.retType, [kind === "+" ? "class" : "object", "selector"].concat(method2.argTypes));
        }
        const signature2 = parseSignature(types2);
        const implementation2 = new NativeCallback(
          makeMethodImplementationWrapper(signature2, method2.implementation),
          signature2.retType.type,
          signature2.argTypes.map(function(arg) {
            return arg.type;
          })
        );
        methodCallbacks.push(implementation2);
        api.class_addMethod(target, selector(name2), implementation2, Memory.allocUtf8String(types2));
      });
    } catch (e) {
      api.objc_disposeClassPair(classHandle);
      throw e;
    }
    api.objc_registerClassPair(classHandle);
    classHandle._methodCallbacks = methodCallbacks;
    Script.bindWeak(classHandle, makeClassDestructor(ptr(classHandle)));
    return new ObjCObject(classHandle);
  }
  function makeClassDestructor(classHandle) {
    return function() {
      api.objc_disposeClassPair(classHandle);
    };
  }
  function registerProtocol(properties) {
    let name = properties.name;
    if (name === void 0)
      name = makeProtocolName();
    const protocols = properties.protocols || [];
    const methods = properties.methods || {};
    protocols.forEach(function(protocol) {
      if (!(protocol instanceof ObjCProtocol))
        throw new Error("Expected protocol");
    });
    const methodSpecs = Object.keys(methods).map(function(rawMethodName) {
      const method2 = methods[rawMethodName];
      const match = /([+\-])\s(\S+)/.exec(rawMethodName);
      if (match === null)
        throw new Error("Invalid method name");
      const kind = match[1];
      const name2 = match[2];
      let types2 = method2.types;
      if (types2 === void 0) {
        types2 = unparseSignature(method2.retType, [kind === "+" ? "class" : "object", "selector"].concat(method2.argTypes));
      }
      return {
        kind,
        name: name2,
        types: types2,
        optional: method2.optional
      };
    });
    const handle2 = api.objc_allocateProtocol(Memory.allocUtf8String(name));
    if (handle2.isNull())
      throw new Error("Unable to register already registered protocol '" + name + "'");
    protocols.forEach(function(protocol) {
      api.protocol_addProtocol(handle2, protocol.handle);
    });
    methodSpecs.forEach(function(spec) {
      const isRequiredMethod = spec.optional ? 0 : 1;
      const isInstanceMethod = spec.kind === "-" ? 1 : 0;
      api.protocol_addMethodDescription(handle2, selector(spec.name), Memory.allocUtf8String(spec.types), isRequiredMethod, isInstanceMethod);
    });
    api.objc_registerProtocol(handle2);
    return new ObjCProtocol(handle2);
  }
  function getHandle(obj) {
    if (obj instanceof NativePointer)
      return obj;
    else if (typeof obj === "object" && obj.hasOwnProperty("handle"))
      return obj.handle;
    else
      throw new Error("Expected NativePointer or ObjC.Object instance");
  }
  function bind(obj, data) {
    const handle2 = getHandle(obj);
    const self = obj instanceof ObjCObject ? obj : new ObjCObject(handle2);
    bindings.set(handle2.toString(), {
      self,
      super: self.$super,
      data
    });
  }
  function unbind(obj) {
    const handle2 = getHandle(obj);
    bindings.delete(handle2.toString());
  }
  function getBoundData(obj) {
    return getBinding(obj).data;
  }
  function getBinding(obj) {
    const handle2 = getHandle(obj);
    const key = handle2.toString();
    let binding = bindings.get(key);
    if (binding === void 0) {
      const self = obj instanceof ObjCObject ? obj : new ObjCObject(handle2);
      binding = {
        self,
        super: self.$super,
        data: {}
      };
      bindings.set(key, binding);
    }
    return binding;
  }
  function enumerateLoadedClasses(...args) {
    const allModules = new ModuleMap();
    let unfiltered = false;
    let callbacks;
    let modules;
    if (args.length === 1) {
      callbacks = args[0];
    } else {
      callbacks = args[1];
      const options = args[0];
      modules = options.ownedBy;
    }
    if (modules === void 0) {
      modules = allModules;
      unfiltered = true;
    }
    const classGetName = api.class_getName;
    const onMatch = callbacks.onMatch.bind(callbacks);
    const swiftNominalTypeDescriptorOffset = (pointerSize === 8 ? 8 : 11) * pointerSize;
    const numClasses = api.objc_getClassList(NULL, 0);
    const classHandles = Memory.alloc(numClasses * pointerSize);
    api.objc_getClassList(classHandles, numClasses);
    for (let i = 0; i !== numClasses; i++) {
      const classHandle = classHandles.add(i * pointerSize).readPointer();
      const rawName = classGetName(classHandle);
      let name = null;
      let modulePath = modules.findPath(rawName);
      const possiblySwift = modulePath === null && (unfiltered || allModules.findPath(rawName) === null);
      if (possiblySwift) {
        name = rawName.readCString();
        const probablySwift = name.indexOf(".") !== -1;
        if (probablySwift) {
          const nominalTypeDescriptor = classHandle.add(swiftNominalTypeDescriptorOffset).readPointer();
          modulePath = modules.findPath(nominalTypeDescriptor);
        }
      }
      if (modulePath !== null) {
        if (name === null)
          name = rawName.readCString();
        onMatch(name, modulePath);
      }
    }
    callbacks.onComplete();
  }
  function enumerateLoadedClassesSync(options = {}) {
    const result = {};
    enumerateLoadedClasses(options, {
      onMatch(name, owner2) {
        let group = result[owner2];
        if (group === void 0) {
          group = [];
          result[owner2] = group;
        }
        group.push(name);
      },
      onComplete() {
      }
    });
    return result;
  }
  function choose(specifier, callbacks) {
    let cls = specifier;
    let subclasses = true;
    if (!(specifier instanceof ObjCObject) && typeof specifier === "object") {
      cls = specifier.class;
      if (specifier.hasOwnProperty("subclasses"))
        subclasses = specifier.subclasses;
    }
    if (!(cls instanceof ObjCObject && (cls.$kind === "class" || cls.$kind === "meta-class")))
      throw new Error("Expected an ObjC.Object for a class or meta-class");
    const matches = get().choose(cls, subclasses).map((handle2) => new ObjCObject(handle2));
    for (const match of matches) {
      const result = callbacks.onMatch(match);
      if (result === "stop")
        break;
    }
    callbacks.onComplete();
  }
  function makeMethodInvocationWrapper(method, owner, superSpecifier, invocationOptions) {
    const sel = method.sel;
    let handle = method.handle;
    let types;
    if (handle === void 0) {
      handle = null;
      types = method.types;
    } else {
      types = api.method_getTypeEncoding(handle).readCString();
    }
    const signature = parseSignature(types);
    const retType = signature.retType;
    const argTypes = signature.argTypes.slice(2);
    const objc_msgSend = superSpecifier ? getMsgSendSuperImpl(signature, invocationOptions) : getMsgSendImpl(signature, invocationOptions);
    const argVariableNames = argTypes.map(function(t, i) {
      return "a" + (i + 1);
    });
    const callArgs = [
      superSpecifier ? "superSpecifier" : "this",
      "sel"
    ].concat(argTypes.map(function(t, i) {
      if (t.toNative) {
        return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ")";
      }
      return argVariableNames[i];
    }));
    let returnCaptureLeft;
    let returnCaptureRight;
    if (retType.type === "void") {
      returnCaptureLeft = "";
      returnCaptureRight = "";
    } else if (retType.fromNative) {
      returnCaptureLeft = "return retType.fromNative.call(this, ";
      returnCaptureRight = ")";
    } else {
      returnCaptureLeft = "return ";
      returnCaptureRight = "";
    }
    const m = eval("var m = function (" + argVariableNames.join(", ") + ") { " + returnCaptureLeft + "objc_msgSend(" + callArgs.join(", ") + ")" + returnCaptureRight + "; }; m;");
    Object.defineProperty(m, "handle", {
      enumerable: true,
      get: getMethodHandle
    });
    m.selector = sel;
    Object.defineProperty(m, "implementation", {
      enumerable: true,
      get() {
        const h = getMethodHandle();
        const impl = new NativeFunction(api.method_getImplementation(h), m.returnType, m.argumentTypes, invocationOptions);
        const newImp = getReplacementMethodImplementation(h);
        if (newImp !== null)
          impl._callback = newImp;
        return impl;
      },
      set(imp) {
        replaceMethodImplementation(getMethodHandle(), imp);
      }
    });
    m.returnType = retType.type;
    m.argumentTypes = signature.argTypes.map((t) => t.type);
    m.types = types;
    Object.defineProperty(m, "symbol", {
      enumerable: true,
      get() {
        return `${method.kind}[${owner.$className} ${selectorAsString(sel)}]`;
      }
    });
    m.clone = function(options) {
      return makeMethodInvocationWrapper(method, owner, superSpecifier, options);
    };
    function getMethodHandle() {
      if (handle === null) {
        if (owner.$kind === "instance") {
          let cur = owner;
          do {
            if ("- forwardingTargetForSelector:" in cur) {
              const target = cur.forwardingTargetForSelector_(sel);
              if (target === null)
                break;
              if (target.$kind !== "instance")
                break;
              const h = api.class_getInstanceMethod(target.$class.handle, sel);
              if (!h.isNull())
                handle = h;
              else
                cur = target;
            } else {
              break;
            }
          } while (handle === null);
        }
        if (handle === null)
          throw new Error("Unable to find method handle of proxied function");
      }
      return handle;
    }
    return m;
  }
  function makeMethodImplementationWrapper(signature, implementation) {
    const retType = signature.retType;
    const argTypes = signature.argTypes;
    const argVariableNames = argTypes.map(function(t, i) {
      if (i === 0)
        return "handle";
      else if (i === 1)
        return "sel";
      else
        return "a" + (i - 1);
    });
    const callArgs = argTypes.slice(2).map(function(t, i) {
      const argVariableName = argVariableNames[2 + i];
      if (t.fromNative) {
        return "argTypes[" + (2 + i) + "].fromNative.call(self, " + argVariableName + ")";
      }
      return argVariableName;
    });
    let returnCaptureLeft;
    let returnCaptureRight;
    if (retType.type === "void") {
      returnCaptureLeft = "";
      returnCaptureRight = "";
    } else if (retType.toNative) {
      returnCaptureLeft = "return retType.toNative.call(self, ";
      returnCaptureRight = ")";
    } else {
      returnCaptureLeft = "return ";
      returnCaptureRight = "";
    }
    const m = eval("var m = function (" + argVariableNames.join(", ") + ") { var binding = getBinding(handle);var self = binding.self;" + returnCaptureLeft + "implementation.call(binding" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; m;");
    return m;
  }
  function makeBlockInvocationWrapper(block, signature, implementation) {
    const retType = signature.retType;
    const argTypes = signature.argTypes.slice(1);
    const argVariableNames = argTypes.map(function(t, i) {
      return "a" + (i + 1);
    });
    const callArgs = argTypes.map(function(t, i) {
      if (t.toNative) {
        return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ")";
      }
      return argVariableNames[i];
    });
    let returnCaptureLeft;
    let returnCaptureRight;
    if (retType.type === "void") {
      returnCaptureLeft = "";
      returnCaptureRight = "";
    } else if (retType.fromNative) {
      returnCaptureLeft = "return retType.fromNative.call(this, ";
      returnCaptureRight = ")";
    } else {
      returnCaptureLeft = "return ";
      returnCaptureRight = "";
    }
    const f = eval("var f = function (" + argVariableNames.join(", ") + ") { " + returnCaptureLeft + "implementation(this" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; f;");
    return f.bind(block);
  }
  function makeBlockImplementationWrapper(block, signature, implementation) {
    const retType = signature.retType;
    const argTypes = signature.argTypes;
    const argVariableNames = argTypes.map(function(t, i) {
      if (i === 0)
        return "handle";
      else
        return "a" + i;
    });
    const callArgs = argTypes.slice(1).map(function(t, i) {
      const argVariableName = argVariableNames[1 + i];
      if (t.fromNative) {
        return "argTypes[" + (1 + i) + "].fromNative.call(this, " + argVariableName + ")";
      }
      return argVariableName;
    });
    let returnCaptureLeft;
    let returnCaptureRight;
    if (retType.type === "void") {
      returnCaptureLeft = "";
      returnCaptureRight = "";
    } else if (retType.toNative) {
      returnCaptureLeft = "return retType.toNative.call(this, ";
      returnCaptureRight = ")";
    } else {
      returnCaptureLeft = "return ";
      returnCaptureRight = "";
    }
    const f = eval("var f = function (" + argVariableNames.join(", ") + ") { if (!this.handle.equals(handle))this.handle = handle;" + returnCaptureLeft + "implementation.call(block" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; f;");
    return f.bind(block);
  }
  function rawFridaType(t) {
    return t === "object" ? "pointer" : t;
  }
  function makeClassName() {
    for (let i = 1; true; i++) {
      const name = "FridaAnonymousClass" + i;
      if (!(name in classRegistry)) {
        return name;
      }
    }
  }
  function makeProtocolName() {
    for (let i = 1; true; i++) {
      const name = "FridaAnonymousProtocol" + i;
      if (!(name in protocolRegistry)) {
        return name;
      }
    }
  }
  function objcMethodName(name) {
    return name.replace(/_/g, ":");
  }
  function jsMethodName(name) {
    let result = name.replace(/:/g, "_");
    if (objCObjectBuiltins.has(result))
      result += "2";
    return result;
  }
  const isaMasks = {
    x64: "0x7ffffffffff8",
    arm64: "0xffffffff8"
  };
  const rawMask = isaMasks[Process.arch];
  if (rawMask !== void 0) {
    const mask = ptr(rawMask);
    readObjectIsa = function(p) {
      return p.readPointer().and(mask);
    };
  } else {
    readObjectIsa = function(p) {
      return p.readPointer();
    };
  }
  function getMsgSendImpl(signature2, invocationOptions2) {
    return resolveMsgSendImpl(msgSendBySignatureId, signature2, invocationOptions2, false);
  }
  function getMsgSendSuperImpl(signature2, invocationOptions2) {
    return resolveMsgSendImpl(msgSendSuperBySignatureId, signature2, invocationOptions2, true);
  }
  function resolveMsgSendImpl(cache, signature2, invocationOptions2, isSuper) {
    if (invocationOptions2 !== defaultInvocationOptions)
      return makeMsgSendImpl(signature2, invocationOptions2, isSuper);
    const { id } = signature2;
    let impl = cache.get(id);
    if (impl === void 0) {
      impl = makeMsgSendImpl(signature2, invocationOptions2, isSuper);
      cache.set(id, impl);
    }
    return impl;
  }
  function makeMsgSendImpl(signature2, invocationOptions2, isSuper) {
    const retType2 = signature2.retType.type;
    const argTypes2 = signature2.argTypes.map(function(t) {
      return t.type;
    });
    const components = ["objc_msgSend"];
    if (isSuper)
      components.push("Super");
    const returnsStruct = retType2 instanceof Array;
    if (returnsStruct && !typeFitsInRegisters(retType2))
      components.push("_stret");
    else if (retType2 === "float" || retType2 === "double")
      components.push("_fpret");
    const name = components.join("");
    return new NativeFunction(api[name], retType2, argTypes2, invocationOptions2);
  }
  function typeFitsInRegisters(type) {
    if (Process.arch !== "x64")
      return false;
    const size = sizeOfTypeOnX64(type);
    return size <= 16;
  }
  function sizeOfTypeOnX64(type) {
    if (type instanceof Array)
      return type.reduce((total, field) => total + sizeOfTypeOnX64(field), 0);
    switch (type) {
      case "bool":
      case "char":
      case "uchar":
        return 1;
      case "int16":
      case "uint16":
        return 2;
      case "int":
      case "int32":
      case "uint":
      case "uint32":
      case "float":
        return 4;
      default:
        return 8;
    }
  }
  function unparseSignature(retType2, argTypes2) {
    const retTypeId = typeIdFromAlias(retType2);
    const argTypeIds = argTypes2.map(typeIdFromAlias);
    const argSizes = argTypeIds.map((id) => singularTypeById[id].size);
    const frameSize = argSizes.reduce((total, size) => total + size, 0);
    let frameOffset = 0;
    return retTypeId + frameSize + argTypeIds.map((id, i) => {
      const result = id + frameOffset;
      frameOffset += argSizes[i];
      return result;
    }).join("");
  }
  function parseSignature(sig) {
    const cursor = [sig, 0];
    parseQualifiers(cursor);
    const retType2 = readType(cursor);
    readNumber(cursor);
    const argTypes2 = [];
    let id = JSON.stringify(retType2.type);
    while (dataAvailable(cursor)) {
      parseQualifiers(cursor);
      const argType = readType(cursor);
      readNumber(cursor);
      argTypes2.push(argType);
      id += JSON.stringify(argType.type);
    }
    return {
      id,
      retType: retType2,
      argTypes: argTypes2
    };
  }
  function parseType(type) {
    const cursor = [type, 0];
    return readType(cursor);
  }
  function readType(cursor) {
    let id = readChar(cursor);
    if (id === "@") {
      let next = peekChar(cursor);
      if (next === "?") {
        id += next;
        skipChar(cursor);
        if (peekChar(cursor) === "<")
          skipExtendedBlock(cursor);
      } else if (next === '"') {
        skipChar(cursor);
        readUntil('"', cursor);
      }
    } else if (id === "^") {
      let next = peekChar(cursor);
      if (next === "@") {
        id += next;
        skipChar(cursor);
      }
    }
    const type = singularTypeById[id];
    if (type !== void 0) {
      return type;
    } else if (id === "[") {
      const length = readNumber(cursor);
      const elementType = readType(cursor);
      skipChar(cursor);
      return arrayType(length, elementType);
    } else if (id === "{") {
      if (!tokenExistsAhead("=", "}", cursor)) {
        readUntil("}", cursor);
        return structType([]);
      }
      readUntil("=", cursor);
      const structFields = [];
      let ch;
      while ((ch = peekChar(cursor)) !== "}") {
        if (ch === '"') {
          skipChar(cursor);
          readUntil('"', cursor);
        }
        structFields.push(readType(cursor));
      }
      skipChar(cursor);
      return structType(structFields);
    } else if (id === "(") {
      readUntil("=", cursor);
      const unionFields = [];
      while (peekChar(cursor) !== ")")
        unionFields.push(readType(cursor));
      skipChar(cursor);
      return unionType(unionFields);
    } else if (id === "b") {
      readNumber(cursor);
      return singularTypeById.i;
    } else if (id === "^") {
      readType(cursor);
      return singularTypeById["?"];
    } else if (modifiers.has(id)) {
      return readType(cursor);
    } else {
      throw new Error("Unable to handle type " + id);
    }
  }
  function skipExtendedBlock(cursor) {
    let ch;
    skipChar(cursor);
    while ((ch = peekChar(cursor)) !== ">") {
      if (peekChar(cursor) === "<") {
        skipExtendedBlock(cursor);
      } else {
        skipChar(cursor);
        if (ch === '"')
          readUntil('"', cursor);
      }
    }
    skipChar(cursor);
  }
  function readNumber(cursor) {
    let result = "";
    while (dataAvailable(cursor)) {
      const c = peekChar(cursor);
      const v = c.charCodeAt(0);
      const isDigit = v >= 48 && v <= 57;
      if (isDigit) {
        result += c;
        skipChar(cursor);
      } else {
        break;
      }
    }
    return parseInt(result);
  }
  function readUntil(token, cursor) {
    const buffer = cursor[0];
    const offset = cursor[1];
    const index = buffer.indexOf(token, offset);
    if (index === -1)
      throw new Error("Expected token '" + token + "' not found");
    const result = buffer.substring(offset, index);
    cursor[1] = index + 1;
    return result;
  }
  function readChar(cursor) {
    return cursor[0][cursor[1]++];
  }
  function peekChar(cursor) {
    return cursor[0][cursor[1]];
  }
  function tokenExistsAhead(token, terminator, cursor) {
    const [buffer, offset] = cursor;
    const tokenIndex = buffer.indexOf(token, offset);
    if (tokenIndex === -1)
      return false;
    const terminatorIndex = buffer.indexOf(terminator, offset);
    if (terminatorIndex === -1)
      throw new Error("Expected to find terminator: " + terminator);
    return tokenIndex < terminatorIndex;
  }
  function skipChar(cursor) {
    cursor[1]++;
  }
  function dataAvailable(cursor) {
    return cursor[1] !== cursor[0].length;
  }
  const qualifierById = {
    "r": "const",
    "n": "in",
    "N": "inout",
    "o": "out",
    "O": "bycopy",
    "R": "byref",
    "V": "oneway"
  };
  function parseQualifiers(cursor) {
    const qualifiers = [];
    while (true) {
      const q = qualifierById[peekChar(cursor)];
      if (q === void 0)
        break;
      qualifiers.push(q);
      skipChar(cursor);
    }
    return qualifiers;
  }
  const idByAlias = {
    "char": "c",
    "int": "i",
    "int16": "s",
    "int32": "i",
    "int64": "q",
    "uchar": "C",
    "uint": "I",
    "uint16": "S",
    "uint32": "I",
    "uint64": "Q",
    "float": "f",
    "double": "d",
    "bool": "B",
    "void": "v",
    "string": "*",
    "object": "@",
    "block": "@?",
    "class": "#",
    "selector": ":",
    "pointer": "^v"
  };
  function typeIdFromAlias(alias) {
    if (typeof alias === "object" && alias !== null)
      return `@"${alias.type}"`;
    const id = idByAlias[alias];
    if (id === void 0)
      throw new Error("No known encoding for type " + alias);
    return id;
  }
  const fromNativeId = function(h) {
    if (h.isNull()) {
      return null;
    } else if (h.toString(16) === this.handle.toString(16)) {
      return this;
    } else {
      return new ObjCObject(h);
    }
  };
  const toNativeId = function(v) {
    if (v === null)
      return NULL;
    const type = typeof v;
    if (type === "string") {
      if (cachedNSStringCtor === null) {
        cachedNSString = classRegistry.NSString;
        cachedNSStringCtor = cachedNSString.stringWithUTF8String_;
      }
      return cachedNSStringCtor.call(cachedNSString, Memory.allocUtf8String(v));
    } else if (type === "number") {
      if (cachedNSNumberCtor === null) {
        cachedNSNumber = classRegistry.NSNumber;
        cachedNSNumberCtor = cachedNSNumber.numberWithDouble_;
      }
      return cachedNSNumberCtor.call(cachedNSNumber, v);
    }
    return v;
  };
  const fromNativeBlock = function(h) {
    if (h.isNull()) {
      return null;
    } else if (h.toString(16) === this.handle.toString(16)) {
      return this;
    } else {
      return new Block(h);
    }
  };
  const toNativeBlock = function(v) {
    return v !== null ? v : NULL;
  };
  const toNativeObjectArray = function(v) {
    if (v instanceof Array) {
      const length = v.length;
      const array = Memory.alloc(length * pointerSize);
      for (let i = 0; i !== length; i++)
        array.add(i * pointerSize).writePointer(toNativeId(v[i]));
      return array;
    }
    return v;
  };
  function arrayType(length, elementType) {
    return {
      type: "pointer",
      read(address) {
        const result = [];
        const elementSize = elementType.size;
        for (let index = 0; index !== length; index++) {
          result.push(elementType.read(address.add(index * elementSize)));
        }
        return result;
      },
      write(address, values) {
        const elementSize = elementType.size;
        values.forEach((value, index) => {
          elementType.write(address.add(index * elementSize), value);
        });
      }
    };
  }
  function structType(fieldTypes) {
    let fromNative, toNative;
    if (fieldTypes.some(function(t) {
      return !!t.fromNative;
    })) {
      const fromTransforms = fieldTypes.map(function(t) {
        if (t.fromNative)
          return t.fromNative;
        else
          return identityTransform;
      });
      fromNative = function(v) {
        return v.map(function(e, i) {
          return fromTransforms[i].call(this, e);
        });
      };
    } else {
      fromNative = identityTransform;
    }
    if (fieldTypes.some(function(t) {
      return !!t.toNative;
    })) {
      const toTransforms = fieldTypes.map(function(t) {
        if (t.toNative)
          return t.toNative;
        else
          return identityTransform;
      });
      toNative = function(v) {
        return v.map(function(e, i) {
          return toTransforms[i].call(this, e);
        });
      };
    } else {
      toNative = identityTransform;
    }
    const [totalSize, fieldOffsets] = fieldTypes.reduce(function(result, t) {
      const [previousOffset, offsets] = result;
      const { size } = t;
      const offset = align(previousOffset, size);
      offsets.push(offset);
      return [offset + size, offsets];
    }, [0, []]);
    return {
      type: fieldTypes.map((t) => t.type),
      size: totalSize,
      read(address) {
        return fieldTypes.map((type, index) => type.read(address.add(fieldOffsets[index])));
      },
      write(address, values) {
        values.forEach((value, index) => {
          fieldTypes[index].write(address.add(fieldOffsets[index]), value);
        });
      },
      fromNative,
      toNative
    };
  }
  function unionType(fieldTypes) {
    const largestType = fieldTypes.reduce(function(largest, t) {
      if (t.size > largest.size)
        return t;
      else
        return largest;
    }, fieldTypes[0]);
    let fromNative, toNative;
    if (largestType.fromNative) {
      const fromTransform = largestType.fromNative;
      fromNative = function(v) {
        return fromTransform.call(this, v[0]);
      };
    } else {
      fromNative = function(v) {
        return v[0];
      };
    }
    if (largestType.toNative) {
      const toTransform = largestType.toNative;
      toNative = function(v) {
        return [toTransform.call(this, v)];
      };
    } else {
      toNative = function(v) {
        return [v];
      };
    }
    return {
      type: [largestType.type],
      size: largestType.size,
      read: largestType.read,
      write: largestType.write,
      fromNative,
      toNative
    };
  }
  const longBits = pointerSize == 8 && Process.platform !== "windows" ? 64 : 32;
  modifiers = /* @__PURE__ */ new Set([
    "j",
    // complex
    "A",
    // atomic
    "r",
    // const
    "n",
    // in
    "N",
    // inout
    "o",
    // out
    "O",
    // by copy
    "R",
    // by ref
    "V",
    // one way
    "+"
    // GNU register
  ]);
  singularTypeById = {
    "c": {
      type: "char",
      size: 1,
      read: (address) => address.readS8(),
      write: (address, value) => {
        address.writeS8(value);
      },
      toNative(v) {
        if (typeof v === "boolean") {
          return v ? 1 : 0;
        }
        return v;
      }
    },
    "i": {
      type: "int",
      size: 4,
      read: (address) => address.readInt(),
      write: (address, value) => {
        address.writeInt(value);
      }
    },
    "s": {
      type: "int16",
      size: 2,
      read: (address) => address.readS16(),
      write: (address, value) => {
        address.writeS16(value);
      }
    },
    "l": {
      type: "int32",
      size: 4,
      read: (address) => address.readS32(),
      write: (address, value) => {
        address.writeS32(value);
      }
    },
    "q": {
      type: "int64",
      size: 8,
      read: (address) => address.readS64(),
      write: (address, value) => {
        address.writeS64(value);
      }
    },
    "C": {
      type: "uchar",
      size: 1,
      read: (address) => address.readU8(),
      write: (address, value) => {
        address.writeU8(value);
      }
    },
    "I": {
      type: "uint",
      size: 4,
      read: (address) => address.readUInt(),
      write: (address, value) => {
        address.writeUInt(value);
      }
    },
    "S": {
      type: "uint16",
      size: 2,
      read: (address) => address.readU16(),
      write: (address, value) => {
        address.writeU16(value);
      }
    },
    "L": {
      type: "uint" + longBits,
      size: longBits / 8,
      read: (address) => address.readULong(),
      write: (address, value) => {
        address.writeULong(value);
      }
    },
    "Q": {
      type: "uint64",
      size: 8,
      read: (address) => address.readU64(),
      write: (address, value) => {
        address.writeU64(value);
      }
    },
    "f": {
      type: "float",
      size: 4,
      read: (address) => address.readFloat(),
      write: (address, value) => {
        address.writeFloat(value);
      }
    },
    "d": {
      type: "double",
      size: 8,
      read: (address) => address.readDouble(),
      write: (address, value) => {
        address.writeDouble(value);
      }
    },
    "B": {
      type: "bool",
      size: 1,
      read: (address) => address.readU8(),
      write: (address, value) => {
        address.writeU8(value);
      },
      fromNative(v) {
        return v ? true : false;
      },
      toNative(v) {
        return v ? 1 : 0;
      }
    },
    "v": {
      type: "void",
      size: 0
    },
    "*": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      fromNative(h) {
        return h.readCString();
      }
    },
    "@": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      fromNative: fromNativeId,
      toNative: toNativeId
    },
    "@?": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      fromNative: fromNativeBlock,
      toNative: toNativeBlock
    },
    "^@": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      toNative: toNativeObjectArray
    },
    "^v": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      }
    },
    "#": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      fromNative: fromNativeId,
      toNative: toNativeId
    },
    ":": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      }
    },
    "?": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      }
    }
  };
  function identityTransform(v) {
    return v;
  }
  function align(value, boundary) {
    const remainder = value % boundary;
    return remainder === 0 ? value : value + (boundary - remainder);
  }
}
var runtime = new Runtime();
var frida_objc_bridge_default = runtime;

// observe.js
var FLUSH_MS = 400;
var MAX_DISTINCT = 8e3;
var MAX_EVENTS = 2e6;
var BASE_WINDOW_MS = 4e3;
var GROUP_WINDOW_MS = 800;
var SEP = String.fromCharCode(1);
var _tally = /* @__PURE__ */ new Map();
var _t0 = Date.now();
var _events = 0;
var _dropped = 0;
var _capped = false;
function emit(cat, key, value) {
  if (_events >= MAX_EVENTS) {
    _capped = true;
    return;
  }
  _events++;
  var k = cat + SEP + (key == null ? "" : key) + SEP + (value == null ? "" : value);
  var row = _tally.get(k);
  if (row === void 0) {
    if (_tally.size >= MAX_DISTINCT) {
      _dropped++;
      _capped = true;
      return;
    }
    _tally.set(k, [1, Date.now() - _t0, 0]);
  } else {
    row[0]++;
  }
}
var GROUP_BASE = "base";
var _probes = [];
var _live = [];
var _detachQueue = [];
var _startedAt = 0;
var _selfRead = false;
var _pendingFiles = [];
var _seenFiles = {};
var _fileBudget = 8;
var _blobs = [];
var _blobBytes = 0;
var MAX_BLOB = 262144;
var MAX_BLOB_TOTAL = 4194304;
function queueFile(path, label) {
  if (!path || _fileBudget <= 0) return;
  if (_seenFiles[path]) return;
  _seenFiles[path] = 1;
  _fileBudget--;
  _pendingFiles.push([path, label, 0]);
}
var _drainFiles = null;
var _blobSeen = {};
function captureBlob(name, b64, nbytes) {
  var fp = nbytes + ":" + b64.length + ":" + b64.slice(0, 48) + ":" + b64.slice(-48);
  if (_blobSeen[fp]) {
    _blobSeen[fp]++;
    emit("BODY", name, "identical body seen again, not stored twice");
    return false;
  }
  if (_blobBytes + nbytes > MAX_BLOB_TOTAL) return false;
  _blobSeen[fp] = 1;
  _blobBytes += nbytes;
  _blobs.push({ n: name, b: b64 });
  return true;
}
function probe(group, target, limit, label, handlers) {
  if (!target) return;
  var p = {
    g: group,
    t: target,
    lim: limit,
    lbl: label,
    h: handlers,
    l: null,
    dl: Infinity
  };
  _probes.push(p);
  if (group === GROUP_BASE) attachProbe(p, BASE_WINDOW_MS);
}
function hotHook(target, limit, label, handlers) {
  probe(GROUP_BASE, target, limit, label, handlers);
}
function attachProbe(p, windowMs) {
  if (p.l) return;
  var n = 0, dead = false, self = null;
  p.dl = _startedAt ? Date.now() + windowMs : Infinity;
  p.win = windowMs;
  try {
    self = Interceptor.attach(p.t, {
      onEnter: function(args) {
        if (dead) return;
        n++;
        if (n > p.lim || (n & 31) === 0 && Date.now() > p.dl) {
          dead = true;
          emit("CAPPED", p.lbl, n > p.lim ? String(p.lim) : p.win + "ms");
          _detachQueue.push(self);
          try {
            self.detach();
          } catch (e) {
          }
          return;
        }
        this._s = true;
        if (p.h.onEnter) {
          try {
            p.h.onEnter.call(this, args);
          } catch (e) {
          }
        }
      },
      onLeave: function(ret) {
        if (this._s && p.h.onLeave) {
          try {
            p.h.onLeave.call(this, ret);
          } catch (e) {
          }
        }
      }
    });
  } catch (e) {
    return;
  }
  p.l = self;
  p.count = function() {
    return n;
  };
  _live.push(p);
}
function detachProbe(p) {
  if (!p.l) return;
  try {
    p.l.detach();
  } catch (e) {
  }
  p.l = null;
  try {
    emit("PROBE", p.g + "|" + p.lbl, "saw " + p.count() + " calls");
  } catch (e) {
  }
  var i = _live.indexOf(p);
  if (i >= 0) _live.splice(i, 1);
}
function armGroup(group, windowMs) {
  var w = windowMs || GROUP_WINDOW_MS;
  var n = 0;
  _probes.forEach(function(p) {
    if (p.g !== group || p.l) return;
    attachProbe(p, w);
    if (p.l) n++;
  });
  emit("PROBE", group, "armed " + n + " hooks for " + w + "ms");
  return n;
}
function disarmGroup(group) {
  var n = 0;
  _live.slice().forEach(function(p) {
    if (group && p.g !== group) return;
    detachProbe(p);
    n++;
  });
  return n;
}
function flush() {
  while (_detachQueue.length) {
    var l = _detachQueue.pop();
    try {
      l.detach();
    } catch (e) {
    }
  }
  var now = Date.now();
  _live.slice().forEach(function(p) {
    if (now > p.dl) {
      emit("CAPPED", p.lbl, p.win + "ms");
      detachProbe(p);
    }
  });
  if (_drainFiles) {
    try {
      _drainFiles();
    } catch (e) {
    }
  }
  var batch = [];
  _tally.forEach(function(row, k) {
    if (row[0] === row[2]) return;
    var p = k.split(SEP);
    batch.push([p[0], p[1], p[2], row[0], row[1]]);
    row[2] = row[0];
  });
  var blobs = _blobs;
  _blobs = [];
  send({
    b: batch,
    dropped: _dropped,
    capped: _capped,
    events: _events,
    live: _live.length,
    hb: 1,
    blobs
  });
}
setInterval(flush, FLUSH_MS);
rpc.exports = {
  flush,
  // Called by the driver the instant the app is resumed. Until this lands the
  // base probes have no deadline, because a spawn-paused process burns no time.
  start: function() {
    _startedAt = Date.now();
    _t0 = _startedAt;
    _live.forEach(function(p) {
      p.dl = _startedAt + BASE_WINDOW_MS;
    });
    return _probes.length;
  },
  // Drops a boundary into the timeline so several posts in one run can still be
  // told apart. The tally is cumulative by design, so the driver diffs counts
  // either side of a mark rather than the script resetting anything.
  mark: function(label) {
    emit("MARK", String(label || "mark"), String(Date.now() - _t0) + "ms");
    return true;
  },
  arm: function(group, windowMs) {
    return armGroup(group, windowMs);
  },
  disarm: function(group) {
    return disarmGroup(group);
  },
  disarmall: function() {
    return disarmGroup(null);
  },
  groups: function() {
    var g = {};
    _probes.forEach(function(p) {
      g[p.g] = (g[p.g] || 0) + 1;
    });
    return g;
  }
};
function budget(limit, label) {
  var n = 0, warned = false;
  return function() {
    if (++n <= limit) return true;
    if (!warned) {
      warned = true;
      emit("CAPPED", label || "a hook", String(limit));
    }
    return false;
  };
}
function dangerousExport(name) {
  try {
    return Module.findGlobalExportByName(name);
  } catch (e) {
    return null;
  }
}
var SYS_NAMELEN = 256;
function cstr(ptr2) {
  try {
    const s = ptr2.readUtf8String();
    return s === null ? null : s.replace(/\0.*$/, "");
  } catch (e) {
    return null;
  }
}
function looksLikeString(ptr2, n) {
  try {
    const a = new Uint8Array(ptr2.readByteArray(n));
    let i = 0;
    while (i < n && a[i] !== 0) {
      if (a[i] < 32 || a[i] > 126) return false;
      i++;
    }
    return i > 0 && i < n;
  } catch (e) {
    return false;
  }
}
var KEYCHAIN_CLASS = {
  genp: "generic password",
  inet: "internet password",
  cert: "certificate",
  keys: "cryptographic key",
  idnt: "identity"
};
if (!frida_objc_bridge_default.available) {
  emit("ERROR", "objc-runtime", "Objective-C runtime not available");
} else {
  let readSockaddr = function(sa) {
    if (sa.isNull()) return null;
    const family = sa.add(1).readU8();
    if (family === AF_INET) {
      const b = new Uint8Array(sa.add(4).readByteArray(4));
      return b.join(".");
    }
    if (family === AF_INET6) {
      const b = new Uint8Array(sa.add(8).readByteArray(16));
      const parts = [];
      for (let i = 0; i < 16; i += 2) parts.push(((b[i] << 8 | b[i + 1]) >>> 0).toString(16));
      return parts.join(":");
    }
    return null;
  }, readPort = function(sa) {
    try {
      const p = sa.add(2).readU16();
      return (p & 255) << 8 | p >> 8 & 255;
    } catch (e) {
      return 0;
    }
  }, isUnspecified = function(addr) {
    return addr === "0.0.0.0" || /^0(:0)*$/.test(addr);
  }, reportDest = function(sa) {
    try {
      if (!sa || sa.isNull()) return;
      const addr = readSockaddr(sa);
      if (!addr || isUnspecified(addr)) return;
      emit("CONNECT", addr, String(readPort(sa)));
    } catch (e) {
    }
  }, objcRet = function(cls, sel2, cat, key, fmt) {
    try {
      const m2 = frida_objc_bridge_default.classes[cls] && frida_objc_bridge_default.classes[cls][sel2];
      if (!m2) return;
      Interceptor.attach(m2.implementation, {
        onLeave: function(ret) {
          try {
            if (ret.isNull()) return;
            const o = new frida_objc_bridge_default.Object(ret);
            emit(cat, key, fmt ? fmt(o) : String(o));
          } catch (e) {
          }
        }
      });
    } catch (e) {
    }
  }, localeId = function(o) {
    try {
      return String(o.localeIdentifier());
    } catch (e) {
      return String(o);
    }
  }, joinArray = function(o) {
    try {
      const n = o.count();
      const out = [];
      for (let i = 0; i < n && i < 12; i++) out.push(String(o.objectAtIndex_(i)));
      return out.join(", ");
    } catch (e) {
      return String(o);
    }
  }, statusHook = function(cls, sel2, key, names) {
    try {
      const k = frida_objc_bridge_default.classes[cls];
      if (!k || !k[sel2]) return;
      Interceptor.attach(k[sel2].implementation, {
        onLeave: function(ret) {
          const v = ret.toInt32();
          emit("PERMS", key, names && names[v] || "status " + v);
        }
      });
    } catch (e) {
    }
  }, tlsAscii = function(buf, n) {
    const bytes = new Uint8Array(buf.readByteArray(n));
    let s = "";
    for (let i = 0; i < n; i++) {
      const ch = bytes[i];
      if (ch === 10 || ch === 13) s += "\n";
      else s += ch >= 32 && ch <= 126 ? String.fromCharCode(ch) : ".";
    }
    return s;
  }, tlsWriteHandler = function(args) {
    const buf = args[1];
    const len = args[2].toInt32();
    if (len < 16 || len > 2e5 || buf.isNull()) return;
    if (!HTTP_START.test(tlsAscii(buf, len < TLS_SNIFF ? len : TLS_SNIFF))) return;
    const lines = tlsAscii(buf, len < TLS_WINDOW ? len : TLS_WINDOW).split("\n");
    let first = (lines[0] || "").slice(0, 160);
    if (!first) return;
    let host = "";
    for (let i = 1; i < lines.length && i < 24; i++) {
      if (lines[i].slice(0, 6).toLowerCase() === "host: ") {
        host = lines[i].slice(6).trim().slice(0, 60);
        break;
      }
    }
    if (host) {
      const sp = first.indexOf(" ");
      if (sp > 0) {
        first = first.slice(0, sp) + " " + host + first.slice(sp + 1).replace(/ HTTP\/[\d.]+$/, "");
      }
    }
    const key = first.slice(0, 200);
    if (seenLines.has(key)) return;
    if (seenLines.size < 400) seenLines.add(key);
    emit("PLAINTEXT", key, null);
  }, b64ptr = function(ptr2, n) {
    try {
      const d = frida_objc_bridge_default.classes.NSData.dataWithBytesNoCopy_length_freeWhenDone_(
        ptr2,
        n,
        false
      );
      if (!d || d.isNull()) return null;
      return String(d.base64EncodedStringWithOptions_(0));
    } catch (e) {
      return null;
    }
  }, publishWriteHandler = function(args) {
    const buf = args[1];
    const len = args[2].toInt32();
    if (len < 16 || len > 2e5 || buf.isNull()) return;
    const sniff = tlsAscii(buf, len < TLS_SNIFF ? len : TLS_SNIFF);
    const http = HTTP_START.test(sniff);
    if (!http && len > 65536) return;
    const n = len < TLS_WINDOW ? len : TLS_WINDOW;
    const text = http || len <= 65536 ? tlsAscii(buf, n) : sniff;
    if (!http && !PUB_NEEDLE.test(text)) return;
    if (http) tlsWriteHandler(args);
    if (PUB_NEEDLE.test(text)) {
      emit(
        "PLAINTEXT",
        "publish needle in SSL_write",
        text.replace(/\s+/g, " ").slice(0, 160)
      );
    }
    if (http || PUB_NEEDLE.test(text)) {
      const take = len < MAX_BLOB ? len : MAX_BLOB;
      const b64 = b64ptr(buf, take);
      if (b64 && captureBlob("SSL_write " + (http ? text.split("\n")[0] || "POST" : "needle"), b64, take)) {
        _pubHits++;
        if (_pubHits >= PUB_DETACH_AFTER) {
          emit("RIG", "publish hook", "self-detached after " + _pubHits + " bodies");
          try {
            disarmGroup("publish");
          } catch (e) {
          }
        }
      }
    }
  }, makeReadHandlers = function(secureTransport) {
    return {
      onEnter: function(args) {
        this.buf = args[1];
        this.got = secureTransport ? args[3] : null;
        this.st = secureTransport;
      },
      onLeave: function(retval) {
        if (this.buf.isNull()) return;
        let len;
        if (this.st) {
          if (retval.toInt32() !== 0 || this.got.isNull()) return;
          len = Number(this.got.readU64());
        } else {
          len = retval.toInt32();
        }
        if (len < 16 || len > 2e5) return;
        const n = len < 128 ? len : 128;
        const bytes = new Uint8Array(this.buf.readByteArray(n));
        let ok = true;
        for (let i = 0; i < 4 && i < n; i++) {
          const ch = bytes[i];
          if (ch < 32 || ch > 126) {
            ok = false;
            break;
          }
        }
        if (!ok) return;
        let s = "";
        for (let i = 0; i < n; i++) {
          const ch = bytes[i];
          s += ch >= 32 && ch <= 126 ? String.fromCharCode(ch) : ".";
        }
        if (!RESP_START.test(s) || RESP_SKIP.test(s)) return;
        const isJson = s[0] === "{" || s[0] === "[";
        const line = isJson ? s.replace(/[\r\n]+/g, " ").slice(0, 120) : s.split("\r")[0].split("\n")[0].slice(0, 90);
        if (seenResp.has(line)) return;
        if (seenResp.size < 400) seenResp.add(line);
        emit("RESPONSE", (isJson ? "JSON  " : "HTTP  ") + line, null);
      }
    };
  }, reportRequest = function(req) {
    try {
      let addr = null;
      try {
        addr = String(req.handle);
      } catch (e) {
      }
      if (addr) {
        if (_reqSeen[addr]) return;
        if (_reqSeenN > 4096) {
          for (const k in _reqSeen) delete _reqSeen[k];
          _reqSeenN = 0;
        }
        _reqSeen[addr] = 1;
        _reqSeenN++;
      }
      const url = req.URL();
      if (!url || url.isNull()) return;
      const scheme = url.scheme();
      if (!scheme || scheme.isNull()) return;
      const s = String(scheme).toLowerCase();
      if (s !== "http" && s !== "https") return;
      const h = url.host();
      if (!h || h.isNull()) return;
      const method2 = req.HTTPMethod ? String(req.HTTPMethod()) : "GET";
      emit("REQUEST", String(h), method2 + " " + String(url.absoluteString()));
      try {
        const hdrs = req.allHTTPHeaderFields();
        if (hdrs && !hdrs.isNull()) {
          const keys = hdrs.allKeys();
          const n = keys.count();
          for (let i = 0; i < n && i < 40; i++) {
            emit("HEADER", String(keys.objectAtIndex_(i)), null);
          }
        }
      } catch (e) {
      }
      try {
        const body = req.HTTPBody();
        if (body && !body.isNull()) {
          const len = body.length();
          let head = "";
          try {
            const s2 = frida_objc_bridge_default.classes.NSString.alloc().initWithData_encoding_(body, 4);
            if (s2 && !s2.isNull()) head = String(s2).slice(0, 100);
          } catch (e) {
          }
          emit(
            "BODY",
            String(h),
            len + " bytes" + (head ? ", starts: " + head.replace(/\s+/g, " ") : "")
          );
          if (len > 0 && len <= MAX_BLOB) {
            try {
              const b64 = String(body.base64EncodedStringWithOptions_(0));
              captureBlob(String(h) + " " + (req.HTTPMethod ? String(req.HTTPMethod()) : "POST") + " " + String(url.path()), b64, len);
            } catch (e) {
            }
          } else if (len > MAX_BLOB) {
            emit("BODY", String(h), "body too large to capture, " + len + " bytes");
          }
        }
      } catch (e) {
      }
    } catch (e) {
    }
  }, mediaHook = function(cls, sel2, handlers) {
    mediaWanted++;
    let why;
    try {
      const k = frida_objc_bridge_default.classes[cls];
      if (!k) why = "class not present on this build";
      else if (k.$ownMethods.indexOf(sel2) === -1) why = "not implemented by this class";
      else if (!k[sel2]) why = "selector did not resolve";
      else {
        Interceptor.attach(k[sel2].implementation, handlers);
        mediaGot++;
        return true;
      }
    } catch (e) {
      why = "attach threw: " + e;
    }
    mediaMissed.push(cls + " " + sel2 + " (" + why + ")");
    return false;
  }, tagValue = function(v) {
    if (!TAG_VALUES) return null;
    try {
      if (v === null || typeof v === "undefined") return null;
      var o = v;
      var cls = String(o.$className);
      if (cls.indexOf("NSData") !== -1 || cls.indexOf("NSConcreteData") !== -1) {
        try {
          return "(" + o.length() + " bytes of data)";
        } catch (e) {
          return "(data)";
        }
      }
      var s = String(o).replace(/\s+/g, " ").trim();
      if (s.length > 72) return s.slice(0, 69) + "...";
      return s.length ? s : null;
    } catch (e) {
      return null;
    }
  }, walkImageTags = function(dict, container) {
    try {
      var keys = dict.allKeys();
      var n = keys.count();
      if (n > 96) n = 96;
      var names = [], raw = [];
      for (var i = 0; i < n; i++) {
        var kobj = keys.objectAtIndex_(i);
        raw.push(kobj);
        names.push(String(kobj));
      }
      var deep = false;
      for (var d = 0; d < names.length; d++) {
        if (DEEP_BLOCKS[names[d]] === 1) {
          deep = true;
          break;
        }
      }
      for (var j = 0; j < names.length; j++) {
        var k = names[j];
        var val = null;
        try {
          val = dict.objectForKey_(raw[j]);
        } catch (e) {
        }
        if (k.charAt(0) === "{") {
          emit("MEDIA_TAG", container + " " + k, deep && DEEP_BLOCKS[k] === 1 ? "(block, opened below)" : "(block, not opened)");
          if (!deep || DEEP_BLOCKS[k] !== 1 || !val) continue;
          try {
            var sub = val;
            if (!sub.allKeys) continue;
            var sk = sub.allKeys(), sn = sk.count();
            if (sn > 80) sn = 80;
            for (var m2 = 0; m2 < sn; m2++) {
              var fk = sk.objectAtIndex_(m2);
              emit(
                "MEDIA_TAG",
                container + " " + k + " " + String(fk),
                tagValue(sub.objectForKey_(fk))
              );
            }
          } catch (e) {
          }
        } else {
          emit("MEDIA_TAG", container + " " + k, tagValue(val));
        }
      }
    } catch (e) {
    }
  }, walkAVTags = function(arr, container) {
    if (!arr) {
      emit("MEDIA_TAG", container + " (absent)", "no metadata array at all");
      return;
    }
    try {
      var n = arr.count();
      if (n > 80) n = 80;
      for (var i = 0; i < n; i++) {
        var it = arr.objectAtIndex_(i);
        var name = null;
        try {
          var id = it.identifier();
          if (id) name = String(id);
        } catch (e) {
        }
        if (!name) {
          var ks = null, kk = null;
          try {
            var x = it.keySpace();
            if (x) ks = String(x);
          } catch (e) {
          }
          try {
            var y = it.key();
            if (y) kk = String(y);
          } catch (e) {
          }
          name = (ks ? ks + "/" : "") + (kk || "unnamed field");
        }
        var val = null;
        try {
          val = tagValue(it.value());
        } catch (e) {
        }
        emit("MEDIA_TAG", container + " " + name, val);
      }
      if (n === 0) emit("MEDIA_TAG", container + " (empty)", "no metadata in this container");
    } catch (e) {
    }
  };
  try {
    const CLLocationManager = frida_objc_bridge_default.classes.CLLocationManager;
    [
      "startUpdatingLocation",
      "requestLocation",
      "requestWhenInUseAuthorization",
      "requestAlwaysAuthorization",
      "startMonitoringSignificantLocationChanges"
    ].forEach(function(sel2) {
      if (CLLocationManager[sel2] === void 0) return;
      Interceptor.attach(CLLocationManager[sel2].implementation, {
        onEnter: function() {
          emit("LOCATION", sel2, null);
        }
      });
    });
    const locGetter = CLLocationManager["- location"];
    if (locGetter) {
      Interceptor.attach(locGetter.implementation, {
        onLeave: function(ret) {
          try {
            if (ret.isNull()) return;
            emit("LOCATION", "location", new frida_objc_bridge_default.Object(ret).toString());
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
    emit("ERROR", "location-hook", String(e));
  }
  try {
    const UIDevice = frida_objc_bridge_default.classes.UIDevice;
    const idfv = UIDevice["- identifierForVendor"];
    if (idfv) {
      Interceptor.attach(idfv.implementation, {
        onLeave: function(ret) {
          try {
            if (ret.isNull()) return;
            emit("IDENTIFIER", "identifierForVendor", new frida_objc_bridge_default.Object(ret).toString());
          } catch (e) {
          }
        }
      });
    }
    ["- systemVersion", "- model", "- name", "- localizedModel"].forEach(function(sel2) {
      const m2 = UIDevice[sel2];
      if (!m2) return;
      const key = sel2.slice(2);
      Interceptor.attach(m2.implementation, {
        onLeave: function(ret) {
          try {
            if (ret.isNull()) return;
            emit("IDENTIFIER", key, new frida_objc_bridge_default.Object(ret).toString());
          } catch (e) {
          }
        }
      });
    });
  } catch (e) {
    emit("ERROR", "identifier-hook", String(e));
  }
  try {
    const SecItemCopyMatching = Module.findGlobalExportByName("SecItemCopyMatching");
    if (SecItemCopyMatching) {
      Interceptor.attach(SecItemCopyMatching, {
        onEnter: function(args) {
          let item = "(unnamed)";
          let kind = "keychain item";
          try {
            const q = new frida_objc_bridge_default.Object(args[0]);
            const cls = q.objectForKey_("class");
            const svc = q.objectForKey_("svce");
            const acct = q.objectForKey_("acct");
            if (cls && !cls.isNull()) {
              const cs = String(cls);
              kind = KEYCHAIN_CLASS[cs] || cs;
            }
            if (svc && !svc.isNull() && String(svc).length) item = String(svc);
            else if (acct && !acct.isNull() && String(acct).length) item = String(acct);
          } catch (e) {
          }
          emit("KEYCHAIN", item, kind);
        }
      });
    }
  } catch (e) {
  }
  try {
    const sysctlbyname = Module.findGlobalExportByName("sysctlbyname");
    if (sysctlbyname) {
      Interceptor.attach(sysctlbyname, {
        onEnter: function(args) {
          this.name = cstr(args[0]) || "?";
          this.oldp = args[1];
          this.oldlenp = args[2];
        },
        onLeave: function(retval) {
          let value = null;
          try {
            if (retval.toInt32() === 0 && !this.oldp.isNull() && !this.oldlenp.isNull()) {
              const n = Number(this.oldlenp.readULong());
              if (n > 0 && n < 1024) {
                if (looksLikeString(this.oldp, n)) value = cstr(this.oldp);
                else if (n === 4) value = String(this.oldp.readU32());
                else if (n === 8) value = String(this.oldp.readU64());
              }
            }
          } catch (e) {
          }
          emit("FINGERPRINT", this.name, value);
        }
      });
    }
    const uname = Module.findGlobalExportByName("uname");
    if (uname) {
      Interceptor.attach(uname, {
        onEnter: function(args) {
          this.buf = args[0];
        },
        onLeave: function(retval) {
          let value = null;
          try {
            if (retval.toInt32() === 0 && !this.buf.isNull()) {
              const release = cstr(this.buf.add(SYS_NAMELEN * 2));
              const machine = cstr(this.buf.add(SYS_NAMELEN * 4));
              value = [release, machine].filter(Boolean).join(" / ") || null;
            }
          } catch (e) {
          }
          emit("FINGERPRINT", "uname", value);
        }
      });
    }
  } catch (e) {
  }
  const AF_INET = 2, AF_INET6 = 30, IFF_UP = 1;
  const seenAddrs = /* @__PURE__ */ new Set();
  hotHook(Module.findGlobalExportByName("getifaddrs"), 48, "interface scans", {
    onEnter: function(args) {
      this.listp = args[0];
    },
    onLeave: function(retval) {
      emit("NETWORK", "getifaddrs", null);
      if (retval.toInt32() !== 0 || this.listp.isNull()) return;
      try {
        let cur = this.listp.readPointer();
        let guard = 0;
        while (!cur.isNull() && guard++ < 256) {
          const name = cstr(cur.add(8).readPointer());
          const flags = cur.add(16).readU32();
          const addr = readSockaddr(cur.add(24).readPointer());
          if (name && addr && flags & IFF_UP) {
            const tag = name + "|" + addr;
            if (!seenAddrs.has(tag)) {
              seenAddrs.add(tag);
              emit("INTERFACE", name, addr);
            }
          }
          cur = cur.readPointer();
        }
      } catch (e) {
      }
    }
  });
  const seenEgress = /* @__PURE__ */ new Set();
  probe("net", dangerousExport("connect"), 120, "outbound connects", {
    onEnter: function(args) {
      reportDest(args[1]);
    }
  });
  probe("net", dangerousExport("connectx"), 120, "outbound connects (nw)", {
    onEnter: function(args) {
      try {
        if (args[1].isNull()) return;
        reportDest(args[1].add(24).readPointer());
      } catch (e) {
      }
    }
  });
  probe("net", dangerousExport("getsockname"), 120, "egress address reads", {
    onEnter: function(args) {
      this.sa = args[1];
    },
    onLeave: function(retval) {
      try {
        if (retval.toInt32() !== 0 || this.sa.isNull()) return;
        const addr = readSockaddr(this.sa);
        if (!addr || isUnspecified(addr) || seenEgress.has(addr)) return;
        seenEgress.add(addr);
        emit("EGRESS", addr, null);
      } catch (e) {
      }
    }
  });
  probe("net", dangerousExport("getaddrinfo"), 120, "name lookups", {
    onEnter: function(args) {
      this.host = args[0].isNull() ? null : cstr(args[0]);
      this.res = args[3];
    },
    onLeave: function(retval) {
      try {
        if (retval.toInt32() !== 0 || !this.host || this.res.isNull()) return;
        let ai = this.res.readPointer();
        let guard = 0;
        const seen = /* @__PURE__ */ new Set();
        while (!ai.isNull() && guard++ < 32) {
          const addr = readSockaddr(ai.add(32).readPointer());
          if (addr && !seen.has(addr)) {
            seen.add(addr);
            emit("DNS", this.host, addr);
          }
          ai = ai.add(40).readPointer();
        }
      } catch (e) {
      }
    }
  });
  const NW_TYPE = [
    "other, which is where a VPN shows up",
    "Wi-Fi",
    "cellular",
    "wired",
    "loopback"
  ];
  probe(
    "net",
    dangerousExport("nw_path_uses_interface_type"),
    150,
    "path type checks",
    {
      onEnter: function(args) {
        this.t = args[1].toInt32();
      },
      onLeave: function(retval) {
        emit(
          "NWPATH",
          NW_TYPE[this.t] || "interface type " + this.t,
          retval.toInt32() ? "yes" : "no"
        );
      }
    }
  );
  try {
    const SIOCGIFCONF = 3222300964, SIOCGIFADDR = 3223349537;
    probe("net", dangerousExport("ioctl"), 150, "ioctl calls", {
      onEnter: function(args) {
        const req = args[1].toUInt32();
        if (req === SIOCGIFCONF) emit("IFENUM", "ioctl SIOCGIFCONF", null);
        else if (req === SIOCGIFADDR) emit("IFENUM", "ioctl SIOCGIFADDR", null);
      }
    });
  } catch (e) {
  }
  objcRet("NSLocale", "+ currentLocale", "LOCALE", "current locale", localeId);
  objcRet("NSLocale", "+ preferredLanguages", "LOCALE", "preferred languages", joinArray);
  objcRet("NSLocale", "+ autoupdatingCurrentLocale", "LOCALE", "current locale", localeId);
  objcRet("NSTimeZone", "+ localTimeZone", "LOCALE", "timezone", function(o) {
    try {
      return String(o.name());
    } catch (e) {
      return String(o);
    }
  });
  objcRet("NSTimeZone", "+ systemTimeZone", "LOCALE", "timezone", function(o) {
    try {
      return String(o.name());
    } catch (e) {
      return String(o);
    }
  });
  objcRet("NSTimeZone", "+ defaultTimeZone", "LOCALE", "timezone", function(o) {
    try {
      return String(o.name());
    } catch (e) {
      return String(o);
    }
  });
  objcRet("NSCalendar", "+ currentCalendar", "LOCALE", "calendar", function(o) {
    try {
      return String(o.calendarIdentifier());
    } catch (e) {
      return String(o);
    }
  });
  try {
    const m2 = frida_objc_bridge_default.classes.NSTimeZone["- secondsFromGMT"];
    if (m2) {
      Interceptor.attach(m2.implementation, {
        onLeave: function(ret) {
          emit("LOCALE", "offset from GMT", ret.toInt32() / 3600 + " hours");
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.UITextInputMode["+ activeInputModes"];
    if (m2) {
      Interceptor.attach(m2.implementation, {
        onLeave: function(ret) {
          try {
            if (ret.isNull()) return;
            const arr = new frida_objc_bridge_default.Object(ret);
            const langs = [];
            const n = arr.count();
            for (let i = 0; i < n && i < 24; i++) {
              const mode = arr.objectAtIndex_(i);
              try {
                const pl = mode.primaryLanguage();
                if (pl && !pl.isNull()) langs.push(String(pl));
              } catch (e) {
              }
            }
            emit("LOCALE", "installed keyboards", langs.join(", ") || String(n));
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  const LOCALE_KEY = /^Apple(Languages|Locale|Keyboards)/i;
  const defBudget = budget(2e4, "NSUserDefaults reads");
  ["- objectForKey:", "- stringForKey:", "- arrayForKey:", "- boolForKey:"].forEach(
    function(sel2) {
      try {
        const m2 = frida_objc_bridge_default.classes.NSUserDefaults[sel2];
        if (!m2) return;
        Interceptor.attach(m2.implementation, {
          onEnter: function(args) {
            this.k = null;
            if (!defBudget()) return;
            try {
              this.k = new frida_objc_bridge_default.Object(args[2]).toString();
            } catch (e) {
              this.k = null;
            }
          },
          onLeave: function(ret) {
            if (!this.k) return;
            let v = null;
            if (LOCALE_KEY.test(this.k)) {
              try {
                if (!ret.isNull()) v = String(new frida_objc_bridge_default.Object(ret));
              } catch (e) {
              }
            }
            emit("SETTINGS", this.k, v);
          }
        });
      } catch (e) {
      }
    }
  );
  objcRet(
    "CTTelephonyNetworkInfo",
    "- subscriberCellularProvider",
    "CARRIER",
    "carrier",
    function(o) {
      try {
        return String(o.carrierName());
      } catch (e) {
        return String(o);
      }
    }
  );
  objcRet(
    "CTTelephonyNetworkInfo",
    "- currentRadioAccessTechnology",
    "CARRIER",
    "radio technology"
  );
  objcRet("CTCarrier", "- carrierName", "CARRIER", "carrier name");
  objcRet("CTCarrier", "- isoCountryCode", "CARRIER", "country code");
  objcRet("CTCarrier", "- mobileCountryCode", "CARRIER", "mobile country code");
  objcRet("CTCarrier", "- mobileNetworkCode", "CARRIER", "mobile network code");
  objcRet(
    "ASIdentifierManager",
    "- advertisingIdentifier",
    "IDENTIFIER",
    "advertisingIdentifier"
  );
  try {
    const m2 = frida_objc_bridge_default.classes.ATTrackingManager && frida_objc_bridge_default.classes.ATTrackingManager["+ trackingAuthorizationStatus"];
    if (m2) {
      Interceptor.attach(m2.implementation, {
        onLeave: function(ret) {
          const S = ["not determined", "restricted", "denied", "authorised"];
          emit("IDENTIFIER", "tracking permission", S[ret.toInt32()] || String(ret.toInt32()));
        }
      });
    }
  } catch (e) {
  }
  [
    "- string",
    "- strings",
    "- items",
    "- URL",
    "- image",
    "- hasStrings",
    "- changeCount"
  ].forEach(function(sel2) {
    try {
      const m2 = frida_objc_bridge_default.classes.UIPasteboard && frida_objc_bridge_default.classes.UIPasteboard[sel2];
      if (!m2) return;
      Interceptor.attach(m2.implementation, {
        onEnter: function() {
          emit("PASTEBOARD", "UIPasteboard " + sel2.slice(2), null);
        }
      });
    } catch (e) {
    }
  });
  try {
    const scr = frida_objc_bridge_default.classes.UIScreen;
    const scrBudget = budget(5e3, "screen reads");
    [
      ["- nativeBounds", "screen resolution"],
      ["- brightness", "screen brightness"]
    ].forEach(function(pair) {
      const m2 = scr && scr[pair[0]];
      if (!m2) return;
      Interceptor.attach(m2.implementation, {
        onEnter: function() {
          if (scrBudget()) emit("DISPLAY", pair[1], null);
        }
      });
    });
  } catch (e) {
  }
  try {
    const dev = frida_objc_bridge_default.classes.UIDevice;
    [["- batteryLevel", "battery level"], ["- batteryState", "battery state"]].forEach(
      function(pair) {
        const m2 = dev && dev[pair[0]];
        if (!m2) return;
        Interceptor.attach(m2.implementation, {
          onEnter: function() {
            emit("DISPLAY", pair[1], null);
          }
        });
      }
    );
  } catch (e) {
  }
  const procBudget = budget(2e4, "NSProcessInfo reads");
  [
    "- physicalMemory",
    "- processorCount",
    "- activeProcessorCount",
    "- systemUptime",
    "- thermalState",
    "- isLowPowerModeEnabled"
  ].forEach(function(sel2) {
    try {
      const m2 = frida_objc_bridge_default.classes.NSProcessInfo && frida_objc_bridge_default.classes.NSProcessInfo[sel2];
      if (!m2) return;
      Interceptor.attach(m2.implementation, {
        onEnter: function() {
          if (procBudget()) emit("DISPLAY", sel2.slice(2), "via NSProcessInfo");
        }
      });
    } catch (e) {
    }
  });
  const diskBudget = budget(2e4, "disk space reads");
  ["statfs", "statfs64"].forEach(function(fn) {
    try {
      probe("fs", dangerousExport(fn), 80, "disk checks (" + fn + ")", {
        onEnter: function() {
          emit("DISPLAY", "free disk space", "read via " + fn);
        }
      });
    } catch (e) {
    }
  });
  try {
    const m2 = frida_objc_bridge_default.classes.UIApplication["- canOpenURL:"];
    if (m2) {
      Interceptor.attach(m2.implementation, {
        onEnter: function(args) {
          try {
            emit("SCHEME", String(new frida_objc_bridge_default.Object(args[2])), null);
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  setTimeout(function() {
    try {
      const info = frida_objc_bridge_default.classes.NSBundle.mainBundle().infoDictionary();
      const q = info.objectForKey_("LSApplicationQueriesSchemes");
      if (q && !q.isNull()) {
        const n = q.count();
        for (let i = 0; i < n && i < 800; i++) {
          emit("QUERYABLE", String(q.objectAtIndex_(i)), null);
        }
      }
    } catch (e) {
    }
  }, 2500);
  try {
    probe("sys", dangerousExport("sysctl"), 200, "numeric sysctl reads", {
      onEnter: function(args) {
        try {
          const n = args[1].toInt32();
          if (n < 1 || n > 8) return;
          const mib = [];
          for (let i = 0; i < n; i++) mib.push(args[0].add(i * 4).readU32());
          const s = mib.join(".");
          if (mib[0] === 1 && mib[1] === 14) {
            emit("TAMPER", "sysctl kern.proc", "reads its own process record, which is the standard debugger check");
          } else {
            emit(
              "DISPLAY",
              "sysctl by number " + s,
              mib[0] === 1 ? "a kernel attribute" : mib[0] === 6 ? "a hardware attribute" : null
            );
          }
        } catch (e) {
        }
      }
    });
  } catch (e) {
  }
  [
    ["_dyld_image_count", "counting loaded libraries"],
    ["_dyld_get_image_name", "reading loaded library names"]
  ].forEach(function(pair) {
    try {
      hotHook(Module.findGlobalExportByName(pair[0]), 64, "dyld scan (" + pair[0] + ")", {
        onEnter: function() {
          emit("TAMPER", pair[0], pair[1]);
        }
      });
    } catch (e) {
    }
  });
  const CS_DEBUGGED = 268435456, CS_GET_TASK_ALLOW = 4;
  ["csops", "csops_audittoken"].forEach(function(fn) {
    probe("sys", dangerousExport(fn), 80, "code-signing checks (" + fn + ")", {
      onEnter: function(args) {
        var opsIdx = fn === "csops" ? 1 : 1;
        this.ops = args[opsIdx].toInt32();
        this.useraddr = fn === "csops" ? args[2] : args[3];
      },
      onLeave: function(ret) {
        if (this.ops !== 0 || this.useraddr.isNull()) {
          emit("TAMPER", "csops (code-signing status)", "read its own signing state");
          return;
        }
        try {
          var flags = this.useraddr.readU32();
          var notes = [];
          if (flags & CS_DEBUGGED) notes.push("debugged");
          if (flags & CS_GET_TASK_ALLOW) notes.push("development build");
          emit(
            "TAMPER",
            "csops (code-signing status)",
            notes.length ? "checked, saw " + notes.join(", ") : "checked, clean"
          );
        } catch (e) {
          emit("TAMPER", "csops (code-signing status)", "read its own signing state");
        }
      }
    });
  });
  const JBPATH = new RegExp([
    "Cydia",
    "Sileo\\.app",
    "Zebra\\.app",
    "MobileSubstrate",
    "substrate",
    "TweakInject",
    "TweakLoader",
    "libhooker",
    "ellekit",
    "frida",
    "cynject",
    "^/var/jb",
    "^/bin/sh",
    "^/bin/bash",
    "^/usr/sbin/sshd",
    "^/etc/apt",
    "^/var/lib/apt",
    "^/var/lib/dpkg",
    "^/Library/MobileSubstrate",
    "^/Applications/"
  ].join("|"), "i");
  ["stat", "lstat", "access"].forEach(function(fn) {
    probe("fs", dangerousExport(fn), 150, "filesystem checks (" + fn + ")", {
      onEnter: function(args) {
        try {
          const path = args[0].readUtf8String();
          if (!path || path.length > 70) return;
          if (JBPATH.test(path)) emit("TAMPER", path, "looked for this file");
        } catch (e) {
        }
      }
    });
  });
  const PERM3 = ["not determined", "restricted", "denied", "allowed"];
  const PERM_PH = ["not determined", "restricted", "denied", "allowed", "limited"];
  const PERM_CL = [
    "not determined",
    "restricted",
    "denied",
    "always allowed",
    "allowed while in use"
  ];
  statusHook("PHPhotoLibrary", "+ authorizationStatus", "photo library", PERM_PH);
  statusHook("PHPhotoLibrary", "+ authorizationStatusForAccessLevel:", "photo library", PERM_PH);
  statusHook("CNContactStore", "+ authorizationStatusForEntityType:", "contacts", PERM3);
  statusHook("EKEventStore", "+ authorizationStatusForEntityType:", "calendar", PERM3);
  statusHook("AVCaptureDevice", "+ authorizationStatusForMediaType:", "camera or microphone", PERM3);
  statusHook("CLLocationManager", "+ authorizationStatus", "location", PERM_CL);
  statusHook("CLLocationManager", "- authorizationStatus", "location", PERM_CL);
  statusHook("ABAddressBook", "+ authorizationStatus", "contacts (legacy API)", PERM3);
  try {
    const m2 = frida_objc_bridge_default.classes.UNUserNotificationCenter && frida_objc_bridge_default.classes.UNUserNotificationCenter["- getNotificationSettingsWithCompletionHandler:"];
    if (m2) {
      Interceptor.attach(m2.implementation, {
        onEnter: function() {
          emit("PERMS", "notifications", "asked");
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.LAContext && frida_objc_bridge_default.classes.LAContext["- canEvaluatePolicy:error:"];
    if (m2) {
      Interceptor.attach(m2.implementation, {
        onLeave: function(ret) {
          emit("PERMS", "biometrics available", ret.toInt32() ? "yes" : "no");
        }
      });
    }
  } catch (e) {
  }
  ["- generateTokenWithCompletionHandler:", "- isSupported"].forEach(function(sel2) {
    try {
      const m2 = frida_objc_bridge_default.classes.DCDevice && frida_objc_bridge_default.classes.DCDevice[sel2];
      if (!m2) return;
      Interceptor.attach(m2.implementation, {
        onEnter: function() {
          emit("PERMS", "Apple device attestation", sel2.slice(2));
        }
      });
    } catch (e) {
    }
  });
  try {
    const m2 = frida_objc_bridge_default.classes.UIFont && frida_objc_bridge_default.classes.UIFont["+ familyNames"];
    if (m2) {
      Interceptor.attach(m2.implementation, {
        onLeave: function(ret) {
          try {
            if (ret.isNull()) return;
            emit(
              "DISPLAY",
              "installed fonts",
              String(new frida_objc_bridge_default.Object(ret).count()) + " families"
            );
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.AVAudioSession && frida_objc_bridge_default.classes.AVAudioSession["- currentRoute"];
    if (m2) {
      const routeBudget = budget(2e3, "audio route reads");
      Interceptor.attach(m2.implementation, {
        onLeave: function(ret) {
          if (!routeBudget()) return;
          try {
            if (ret.isNull()) return;
            const outs = new frida_objc_bridge_default.Object(ret).outputs();
            const n = outs.count();
            const names = [];
            for (let i = 0; i < n && i < 4; i++) {
              names.push(String(outs.objectAtIndex_(i).portType()));
            }
            emit("DISPLAY", "audio output", names.join(", ") || "none");
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.NSHTTPCookieStorage && frida_objc_bridge_default.classes.NSHTTPCookieStorage["- cookies"];
    if (m2) {
      const cookieBudget = budget(2e3, "cookie store reads");
      Interceptor.attach(m2.implementation, {
        onLeave: function(ret) {
          if (!cookieBudget()) return;
          try {
            if (ret.isNull()) return;
            emit(
              "DISPLAY",
              "stored cookies",
              String(new frida_objc_bridge_default.Object(ret).count()) + " cookies"
            );
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  try {
    probe("net", dangerousExport("res_9_getservers"), 40, "resolver list reads", {
      onEnter: function() {
        emit("DISPLAY", "DNS servers", "read the resolver list");
      }
    });
  } catch (e) {
  }
  try {
    probe("net", dangerousExport("SCNetworkReachabilityGetFlags"), 120, "reachability checks", {
      onEnter: function() {
        emit("DISPLAY", "connection reachability", "via SystemConfiguration");
      }
    });
  } catch (e) {
  }
  [
    "- startAccelerometerUpdates",
    "- startAccelerometerUpdatesToQueue:withHandler:",
    "- startGyroUpdates",
    "- startGyroUpdatesToQueue:withHandler:",
    "- startMagnetometerUpdates",
    "- startMagnetometerUpdatesToQueue:withHandler:",
    "- startDeviceMotionUpdates",
    "- startDeviceMotionUpdatesToQueue:withHandler:",
    "- startDeviceMotionUpdatesUsingReferenceFrame:toQueue:withHandler:"
  ].forEach(function(sel2) {
    try {
      const m2 = frida_objc_bridge_default.classes.CMMotionManager && frida_objc_bridge_default.classes.CMMotionManager[sel2];
      if (!m2) return;
      Interceptor.attach(m2.implementation, {
        onEnter: function() {
          emit(
            "SENSOR",
            sel2.replace(/^- start/, "").replace(/(ToQueue.*|Updates.*)$/, "").toLowerCase() || "motion",
            "started collecting"
          );
        }
      });
    } catch (e) {
    }
  });
  ["- accelerometerData", "- gyroData", "- magnetometerData", "- deviceMotion"].forEach(function(sel2) {
    try {
      const m2 = frida_objc_bridge_default.classes.CMMotionManager && frida_objc_bridge_default.classes.CMMotionManager[sel2];
      if (!m2) return;
      const b = budget(5e3, "motion sample reads");
      Interceptor.attach(m2.implementation, {
        onEnter: function() {
          if (b()) emit("SENSOR", sel2.slice(2), "read a sample");
        }
      });
    } catch (e) {
    }
  });
  [
    "- startPedometerUpdatesFromDate:withHandler:",
    "- queryPedometerDataFromDate:toDate:withHandler:"
  ].forEach(function(sel2) {
    try {
      const m2 = frida_objc_bridge_default.classes.CMPedometer && frida_objc_bridge_default.classes.CMPedometer[sel2];
      if (!m2) return;
      Interceptor.attach(m2.implementation, {
        onEnter: function() {
          emit("SENSOR", "step count", "asked for walking data");
        }
      });
    } catch (e) {
    }
  });
  try {
    const m2 = frida_objc_bridge_default.classes.CMAltimeter && frida_objc_bridge_default.classes.CMAltimeter["- startRelativeAltitudeUpdatesToQueue:withHandler:"];
    if (m2) {
      Interceptor.attach(m2.implementation, {
        onEnter: function() {
          emit("SENSOR", "barometric altitude", "started collecting, which gives floor level");
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.CMMotionActivityManager && frida_objc_bridge_default.classes.CMMotionActivityManager["- startActivityUpdatesToQueue:withHandler:"];
    if (m2) {
      Interceptor.attach(m2.implementation, {
        onEnter: function() {
          emit("SENSOR", "motion activity", "whether you are walking, cycling or driving");
        }
      });
    }
  } catch (e) {
  }
  try {
    const p = Module.findGlobalExportByName("CNCopyCurrentNetworkInfo");
    if (p) {
      Interceptor.attach(p, {
        onEnter: function() {
          emit("INTERFACE_ID", "Wi-Fi network identity", "asked for SSID and BSSID");
        }
      });
    }
  } catch (e) {
  }
  ["- SSID", "- BSSID"].forEach(function(sel2) {
    try {
      const m2 = frida_objc_bridge_default.classes.NEHotspotNetwork && frida_objc_bridge_default.classes.NEHotspotNetwork[sel2];
      if (!m2) return;
      Interceptor.attach(m2.implementation, {
        onLeave: function(ret) {
          try {
            if (ret.isNull()) return;
            emit(
              "INTERFACE_ID",
              sel2 === "- SSID" ? "Wi-Fi network name" : "Wi-Fi router address",
              String(new frida_objc_bridge_default.Object(ret))
            );
          } catch (e) {
          }
        }
      });
    } catch (e) {
    }
  });
  [
    "- allInstalledApplications",
    "- applicationsAvailableForOpeningURL:",
    "- installedPlugins"
  ].forEach(function(sel2) {
    try {
      const k = frida_objc_bridge_default.classes.LSApplicationWorkspace;
      if (!k || !k[sel2]) return;
      Interceptor.attach(k[sel2].implementation, {
        onLeave: function(ret) {
          let n = "";
          try {
            if (!ret.isNull()) n = String(new frida_objc_bridge_default.Object(ret).count()) + " apps";
          } catch (e) {
          }
          emit("SCHEME", "listed every installed app", n || sel2.slice(2));
        }
      });
    } catch (e) {
    }
  });
  const HTTP_START = /^(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS) |^Host: /;
  const seenLines = /* @__PURE__ */ new Set();
  const TLS_SNIFF = 16;
  const TLS_WINDOW = 1200;
  ["SSLWrite", "SSL_write"].forEach(function(nm) {
    probe(
      "tls",
      dangerousExport(nm),
      60,
      "TLS write (" + nm + ")",
      { onEnter: tlsWriteHandler }
    );
  });
  const PUB_NEEDLE = /aweme|CANARY|11\.1111|22\.2222|GPSCoordinates|ISO6709/i;
  _pubHits = 0;
  PUB_DETACH_AFTER = 2;
  probe(
    "publish",
    dangerousExport("SSL_write"),
    2e4,
    "publish TLS write",
    { onEnter: publishWriteHandler }
  );
  const RESP_START = /^HTTP\/[0-9]|^\{"|^\[\{|^\[\s*"/;
  const RESP_SKIP = /Switching Protocols|Content-Type: (video|audio|image)|Partial Content/i;
  const seenResp = /* @__PURE__ */ new Set();
  probe(
    "tls",
    dangerousExport("SSLRead"),
    60,
    "TLS read (SSLRead)",
    makeReadHandlers(true)
  );
  probe(
    "tls",
    dangerousExport("SSL_read"),
    60,
    "TLS read (SSL_read)",
    makeReadHandlers(false)
  );
  try {
    const proxy = Module.findGlobalExportByName("CFNetworkCopySystemProxySettings");
    if (proxy) {
      Interceptor.attach(proxy, {
        onEnter: function() {
          emit("PROXY", "proxy config", null);
        }
      });
    }
  } catch (e) {
  }
  try {
    const NEVPNManager = frida_objc_bridge_default.classes.NEVPNManager;
    if (NEVPNManager && NEVPNManager["- connection"]) {
      Interceptor.attach(NEVPNManager["- connection"].implementation, {
        onEnter: function() {
          emit("PROXY", "VPN status", null);
        }
      });
    }
  } catch (e) {
  }
  try {
    const NSURLSession = frida_objc_bridge_default.classes.NSURLSession;
    ["- dataTaskWithRequest:completionHandler:", "- dataTaskWithRequest:"].forEach(function(sel2) {
      if (!NSURLSession || !NSURLSession[sel2]) return;
      Interceptor.attach(NSURLSession[sel2].implementation, {
        onEnter: function(args) {
          try {
            reportRequest(new frida_objc_bridge_default.Object(args[2]));
          } catch (e) {
          }
        }
      });
    });
  } catch (e) {
    emit("ERROR", "request-hook", String(e));
  }
  try {
    const seenImpl = {};
    ["__NSCFLocalSessionTask", "__NSCFURLSessionTask", "NSURLSessionTask"].forEach(function(cn) {
      const klass = frida_objc_bridge_default.classes[cn];
      if (!klass || !klass["- resume"]) return;
      const impl = klass["- resume"].implementation;
      const addr = String(impl);
      if (seenImpl[addr]) {
        emit(
          "RIG",
          "shared -resume implementation, hooked once",
          cn + " inherits it from " + seenImpl[addr]
        );
        return;
      }
      seenImpl[addr] = cn;
      Interceptor.attach(impl, {
        onEnter: function(args) {
          try {
            const task = new frida_objc_bridge_default.Object(args[0]);
            if (task.originalRequest === void 0) return;
            const req = task.originalRequest();
            if (req) reportRequest(req);
          } catch (e) {
          }
        }
      });
    });
  } catch (e) {
  }
  const _reqSeen = {};
  let _reqSeenN = 0;
  let mediaWanted = 0, mediaGot = 0;
  const mediaMissed = [];
  TAG_VALUES = true;
  DEEP_BLOCKS = {
    "{TIFF}": 1,
    "{Exif}": 1,
    "{GPS}": 1,
    "{IPTC}": 1,
    "{MakerApple}": 1,
    "{ExifAux}": 1,
    "{XMP}": 1,
    "{DNG}": 1,
    "{Photoshop}": 1,
    "{HEICS}": 1
  };
  mediaHook("PHPickerViewController", "- initWithConfiguration:", {
    onEnter: function() {
      emit("MEDIA", "system photo picker", "opened, runs outside the app, no permission needed");
    }
  });
  const PICKER_SRC = ["photo library", "camera", "saved photos album"];
  mediaHook("UIImagePickerController", "- setSourceType:", {
    onEnter: function(args) {
      let t = -1;
      try {
        t = Number(args[2].toInt32());
      } catch (e) {
      }
      emit("MEDIA", "in-app camera or picker", PICKER_SRC[t] || "source " + t);
    }
  });
  mediaHook("AVCaptureSession", "- startRunning", {
    onEnter: function() {
      emit("MEDIA", "capture session", "started, camera or mic is live");
    }
  });
  mediaHook("AVCaptureSession", "- addInput:", {
    onEnter: function(args) {
      try {
        const inp = new frida_objc_bridge_default.Object(args[2]);
        if (inp.device === void 0) return;
        const dev = inp.device();
        if (!dev || dev.isNull()) return;
        emit("MEDIA", "capture device opened", String(dev.localizedName()));
      } catch (e) {
      }
    }
  });
  const audioCatBudget = budget(4e3, "audio session category sets");
  [
    "- setCategory:error:",
    "- setCategory:withOptions:error:",
    "- setCategory:mode:options:error:"
  ].forEach(function(sel2) {
    mediaHook("AVAudioSession", sel2, {
      onEnter: function(args) {
        if (!audioCatBudget()) return;
        try {
          const cat = String(new frida_objc_bridge_default.Object(args[2]));
          if (cat.indexOf("Record") === -1) return;
          emit(
            "MEDIA",
            "audio session set to record",
            cat.replace("AVAudioSessionCategory", "")
          );
        } catch (e) {
        }
      }
    });
  });
  mediaHook("AVAudioSession", "- recordPermission", {
    onLeave: function() {
      emit("MEDIA", "microphone permission", "checked");
    }
  });
  ["CGImageSourceCopyPropertiesAtIndex", "CGImageSourceCopyProperties"].forEach(
    function(nm) {
      const p = dangerousExport(nm);
      if (!p) return;
      const b = budget(400, "image metadata reads (" + nm + ")");
      const tb = budget(140, "image tag inventory (" + nm + ")");
      Interceptor.attach(p, {
        onLeave: function(ret) {
          try {
            if (ret.isNull()) return;
            if (_selfRead) return;
            emit("MEDIA_META", "image metadata block", "opened via " + nm);
            if (!b()) return;
            const d = new frida_objc_bridge_default.Object(ret);
            if (tb()) walkImageTags(d, "image");
            const keys = d.allKeys();
            const n = keys.count();
            for (let i = 0; i < n && i < 40; i++) {
              const k = String(keys.objectAtIndex_(i));
              if (k.indexOf("GPS") !== -1) {
                emit(
                  "MEDIA_META",
                  "GPS block read out of the file",
                  "a location read that needs no permission"
                );
              } else if (k.indexOf("Exif") !== -1) {
                emit("MEDIA_META", "EXIF block", "capture time and camera settings");
              } else if (k.indexOf("TIFF") !== -1) {
                emit("MEDIA_META", "TIFF block", "camera make and model");
              } else {
                emit("MEDIA_META", "other metadata fields", k);
              }
            }
          } catch (e) {
          }
        }
      });
    }
  );
  const assetMetaBudget = budget(300, "video metadata reads");
  const avTagBudget = budget(120, "video tag inventory");
  ["AVAsset", "AVURLAsset"].forEach(function(cls) {
    ["- commonMetadata", "- metadata"].forEach(function(sel2) {
      mediaHook(cls, sel2, {
        onLeave: function(ret) {
          try {
            if (ret.isNull()) return;
            if (_selfRead) return;
            emit("MEDIA_META", "video metadata block", "read from the file");
            if (!assetMetaBudget()) return;
            const arr = new frida_objc_bridge_default.Object(ret);
            if (avTagBudget()) walkAVTags(arr, "video " + sel2.slice(2));
            const n = arr.count();
            for (let i = 0; i < n && i < 40; i++) {
              const it = arr.objectAtIndex_(i);
              let ck = null;
              try {
                const c = it.commonKey();
                if (c && !c.isNull()) ck = String(c);
              } catch (e) {
              }
              if (ck === "location") {
                emit(
                  "MEDIA_META",
                  "geotag inside the video",
                  "a location read that needs no permission"
                );
              } else if (ck === "creationDate" || ck === "make" || ck === "model") {
                emit("MEDIA_META", "video " + ck, "read from the file");
              } else if (ck) {
                emit("MEDIA_META", "other video metadata fields", ck);
              } else {
                emit(
                  "MEDIA_META",
                  "other video metadata fields",
                  "format-specific field, no common key"
                );
              }
            }
            if (n === 0) {
              emit(
                "MEDIA_META",
                "video metadata came back empty",
                "the file carried no metadata to read"
              );
            }
          } catch (e) {
          }
        }
      });
    });
  });
  const phAssetBudget = budget(1200, "photo library asset reads");
  [
    ["- location", "library geotag on the chosen item"],
    ["- creationDate", "when the chosen item was shot"],
    ["- modificationDate", "when the chosen item was last edited"],
    ["- localIdentifier", "stable library ID of the chosen item"]
  ].forEach(function(pair) {
    mediaHook("PHAsset", pair[0], {
      onLeave: function(ret) {
        if (ret.isNull()) return;
        if (_selfRead) return;
        if (!phAssetBudget()) return;
        emit("MEDIA_META", pair[1], "read");
      }
    });
  });
  mediaHook("PHObject", "- localIdentifier", {
    onLeave: function(ret) {
      if (ret.isNull() || _selfRead) return;
      if (!phAssetBudget()) return;
      emit("MEDIA_META", "stable library ID of the chosen item", "read");
    }
  });
  const PH_SOURCE = {
    0: "none",
    1: "user library",
    2: "cloud shared",
    4: "iTunes synced"
  };
  const PH_SUBTYPE = [
    [1, "panorama"],
    [2, "HDR"],
    [4, "screenshot"],
    [8, "LIVE PHOTO"],
    [16, "depth effect"],
    [65536, "streamed video"],
    [131072, "high frame rate"],
    [262144, "timelapse"],
    [2097152, "cinematic"]
  ];
  mediaHook("PHAsset", "- sourceType", {
    onLeave: function(ret) {
      if (_selfRead || !phAssetBudget()) return;
      let v = -1;
      try {
        v = ret.toUInt32();
      } catch (e) {
        return;
      }
      emit("MEDIA_TAG", "library sourceType", PH_SOURCE[v] || "value " + v);
    }
  });
  mediaHook("PHAsset", "- mediaSubtypes", {
    onLeave: function(ret) {
      if (_selfRead || !phAssetBudget()) return;
      let v = 0;
      try {
        v = ret.toUInt32();
      } catch (e) {
        return;
      }
      if (v === 0) {
        emit("MEDIA_TAG", "library mediaSubtypes", "none");
        return;
      }
      PH_SUBTYPE.forEach(function(s) {
        if (v & s[0]) emit("MEDIA_TAG", "library mediaSubtypes", s[1]);
      });
    }
  });
  [
    ["- pixelWidth", "library pixelWidth"],
    ["- pixelHeight", "library pixelHeight"],
    ["- burstIdentifier", "library burstIdentifier"],
    ["- playbackStyle", "library playbackStyle"]
  ].forEach(function(pair) {
    mediaHook("PHAsset", pair[0], {
      onLeave: function(ret) {
        if (_selfRead || !phAssetBudget()) return;
        let v = null;
        try {
          v = pair[0].indexOf("Identifier") !== -1 ? ret.isNull() ? "absent" : String(new frida_objc_bridge_default.Object(ret)) : String(ret.toUInt32());
        } catch (e) {
          return;
        }
        emit("MEDIA_TAG", pair[1], v);
      }
    });
  });
  [
    ["- originalFilename", "resource originalFilename"],
    ["- uniformTypeIdentifier", "resource uniformTypeIdentifier"]
  ].forEach(function(pair) {
    mediaHook("PHAssetResource", pair[0], {
      onLeave: function(ret) {
        if (ret.isNull() || _selfRead) return;
        if (!phAssetBudget()) return;
        try {
          emit("MEDIA_TAG", pair[1], String(new frida_objc_bridge_default.Object(ret)));
        } catch (e) {
        }
      }
    });
  });
  mediaHook("AVAssetWriter", "- startWriting", {
    onEnter: function() {
      emit("MEDIA", "video encode started", "AVAssetWriter");
    }
  });
  mediaHook("AVAssetExportSession", "- exportAsynchronouslyWithCompletionHandler:", {
    onEnter: function() {
      emit("MEDIA", "video export started", "AVAssetExportSession");
    }
  });
  try {
    const vt = dangerousExport("VTCompressionSessionCreate");
    if (vt) {
      const b = budget(50, "hardware encoder sessions");
      Interceptor.attach(vt, {
        onEnter: function() {
          if (b()) emit("MEDIA", "hardware video encoder", "compression session created");
        }
      });
    }
  } catch (e) {
  }
  try {
    const mdAt = dangerousExport("CGImageSourceCopyMetadataAtIndex");
    if (mdAt) {
      const xb = budget(60, "XMP metadata reads");
      const copyTags = dangerousExport("CGImageMetadataCopyTags");
      const tagName = dangerousExport("CGImageMetadataTagCopyName");
      const tagPrefix = dangerousExport("CGImageMetadataTagCopyPrefix");
      const fn = function(p) {
        try {
          return p ? new NativeFunction(p, "pointer", ["pointer"]) : null;
        } catch (e) {
          return null;
        }
      };
      const fTags = fn(copyTags), fName = fn(tagName), fPrefix = fn(tagPrefix);
      Interceptor.attach(mdAt, {
        onLeave: function(ret) {
          try {
            if (ret.isNull() || _selfRead) return;
            emit("MEDIA_META", "XMP metadata block", "opened out of the file");
            if (!xb() || !fTags) return;
            const tags = fTags(ret);
            if (tags.isNull()) return;
            const arr = new frida_objc_bridge_default.Object(tags);
            let n = arr.count();
            if (n > 80) n = 80;
            for (let i = 0; i < n; i++) {
              const t = arr.objectAtIndex_(i).handle;
              let pfx = "", nm = "?";
              try {
                if (fPrefix) {
                  const p = fPrefix(t);
                  if (!p.isNull()) pfx = String(new frida_objc_bridge_default.Object(p)) + ":";
                }
              } catch (e) {
              }
              try {
                if (fName) {
                  const q = fName(t);
                  if (!q.isNull()) nm = String(new frida_objc_bridge_default.Object(q));
                }
              } catch (e) {
              }
              emit("MEDIA_TAG", "XMP " + pfx + nm, null);
            }
            if (n === 0) emit("MEDIA_TAG", "XMP (empty)", "no XMP tags in this file");
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  try {
    const gst = Module.findGlobalExportByName("CMFormatDescriptionGetMediaSubType");
    const fSub = gst ? new NativeFunction(gst, "uint32", ["pointer"]) : null;
    const fourcc = function(v) {
      let s = "";
      for (let i = 3; i >= 0; i--) {
        const c = v >> i * 8 & 255;
        s += c >= 32 && c <= 126 ? String.fromCharCode(c) : ".";
      }
      return s;
    };
    const fdBudget = budget(60, "track format description reads");
    mediaHook("AVAssetTrack", "- formatDescriptions", {
      onLeave: function(ret) {
        try {
          if (ret.isNull() || _selfRead || !fSub) return;
          if (!fdBudget()) return;
          const arr = new frida_objc_bridge_default.Object(ret);
          let n = arr.count();
          if (n > 8) n = 8;
          for (let i = 0; i < n; i++) {
            emit(
              "MEDIA_TAG",
              "track codec",
              fourcc(fSub(arr.objectAtIndex_(i).handle))
            );
          }
        } catch (e) {
        }
      }
    });
  } catch (e) {
  }
  ["- initWithURL:options:"].forEach(function(sel2) {
    mediaHook("AVURLAsset", sel2, {
      onEnter: function(args) {
        try {
          if (_selfRead) return;
          const u = new frida_objc_bridge_default.Object(args[2]);
          if (!u.isFileURL || !u.isFileURL()) return;
          const p = String(u.path());
          emit("MEDIA", "opened a media file", String(u.lastPathComponent()));
          queueFile(p, "INPUT");
        } catch (e) {
        }
      }
    });
  });
  ["AVAsset", "AVURLAsset"].forEach(function(cls) {
    mediaHook(cls, "- tracksWithMediaType:", {
      onEnter: function(args) {
        try {
          if (_selfRead) return;
          this._mt = String(new frida_objc_bridge_default.Object(args[2]));
        } catch (e) {
        }
      },
      onLeave: function(ret) {
        try {
          if (_selfRead || !this._mt) return;
          if (this._mt !== "meta" && this._mt !== "mebx") return;
          let n = 0;
          try {
            n = new frida_objc_bridge_default.Object(ret).count();
          } catch (e) {
          }
          emit(
            "MEDIA",
            "asked for the timed-metadata tracks",
            this._mt + ", " + n + " returned"
          );
        } catch (e) {
        }
      }
    });
  });
  mediaHook("AVAssetReaderTrackOutput", "- initWithTrack:outputSettings:", {
    onEnter: function(args) {
      try {
        if (_selfRead) return;
        const track = new frida_objc_bridge_default.Object(args[2]);
        const mt = String(track.mediaType());
        emit("MEDIA", "built a sample reader over a track", mt);
        if (mt === "meta" || mt === "mebx") {
          emit(
            "MEDIA_TAG",
            "reading timed metadata samples",
            "per-frame track, this is where detected-face lives"
          );
        }
      } catch (e) {
      }
    }
  });
  ["- initWithIdentifiers:"].forEach(function(sel2) {
    mediaHook("AVPlayerItemMetadataOutput", sel2, {
      onEnter: function(args) {
        try {
          if (_selfRead) return;
          let ids = "(all identifiers)";
          try {
            const a = new frida_objc_bridge_default.Object(args[2]);
            if (!a.isNull || !a.isNull()) ids = String(a);
          } catch (e) {
          }
          emit("MEDIA_TAG", "subscribed to timed metadata", ids.slice(0, 120));
        } catch (e) {
        }
      }
    });
  });
  ["AVAssetExportSession", "AVAssetWriter"].forEach(function(cls) {
    mediaHook(cls, "- setOutputURL:", {
      onEnter: function(args) {
        try {
          if (_selfRead) return;
          const u = new frida_objc_bridge_default.Object(args[2]);
          if (!u.path) return;
          const p = String(u.path());
          emit("MEDIA", "encoder output file", String(u.lastPathComponent()));
          queueFile(p, "OUTPUT");
        } catch (e) {
        }
      }
    });
  });
  mediaHook("AVAssetWriter", "- initWithURL:fileType:error:", {
    onEnter: function(args) {
      try {
        if (_selfRead) return;
        const u = new frida_objc_bridge_default.Object(args[2]);
        if (!u.path) return;
        emit("MEDIA", "encoder output file", String(u.lastPathComponent()));
        queueFile(String(u.path()), "OUTPUT");
      } catch (e) {
      }
    }
  });
  ["AVAssetExportSession", "AVAssetWriter"].forEach(function(cls) {
    mediaHook(cls, "- setMetadata:", {
      onEnter: function(args) {
        try {
          if (_selfRead) return;
          const arr = new frida_objc_bridge_default.Object(args[2]);
          if (!arr || !arr.count) return;
          walkAVTags(arr, "written into the export");
        } catch (e) {
        }
      }
    });
  });
  const MEDIA_EXT = /\.(mov|mp4|m4v|heic|heif|jpg|jpeg|png|webp|gif|aae|avci)$/i;
  const attrBudget = budget(120, "media file attribute reads");
  mediaHook("NSFileManager", "- attributesOfItemAtPath:error:", {
    onEnter: function(args) {
      this._p = null;
      try {
        if (_selfRead) return;
        const p = String(new frida_objc_bridge_default.Object(args[2]));
        if (MEDIA_EXT.test(p)) this._p = p;
      } catch (e) {
      }
    },
    onLeave: function(ret) {
      try {
        if (!this._p || ret.isNull() || !attrBudget()) return;
        const d = new frida_objc_bridge_default.Object(ret);
        const name = this._p.split("/").pop();
        try {
          emit("MEDIA_TAG", "file size", String(d.objectForKey_("NSFileSize")) + " bytes (" + name + ")");
        } catch (e) {
        }
        ["NSFileCreationDate", "NSFileModificationDate"].forEach(function(k) {
          try {
            const v = d.objectForKey_(k);
            if (v && !v.isNull()) {
              emit("MEDIA_TAG", "file " + k.replace("NSFile", ""), String(v));
            }
          } catch (e) {
          }
        });
      } catch (e) {
      }
    }
  });
  [
    "- uploadTaskWithRequest:fromData:",
    "- uploadTaskWithRequest:fromFile:",
    "- uploadTaskWithRequest:fromData:completionHandler:",
    "- uploadTaskWithRequest:fromFile:completionHandler:",
    "- uploadTaskWithStreamedRequest:"
  ].forEach(function(sel2) {
    mediaHook("NSURLSession", sel2, {
      onEnter: function(args) {
        try {
          const req = new frida_objc_bridge_default.Object(args[2]);
          let host = "unknown host";
          try {
            const u = req.URL();
            if (u) {
              const h = u.host();
              if (h) host = String(h);
            }
          } catch (e) {
          }
          let what = "streamed body, size not known yet";
          if (sel2.indexOf("fromData:") !== -1) {
            try {
              what = new frida_objc_bridge_default.Object(args[3]).length() + " bytes from memory";
            } catch (e) {
            }
          } else if (sel2.indexOf("fromFile:") !== -1) {
            try {
              const f2 = new frida_objc_bridge_default.Object(args[3]);
              what = "file " + String(f2.lastPathComponent());
              if (f2.path) queueFile(String(f2.path()), "UPLOADED");
            } catch (e) {
            }
          }
          emit("MEDIA", "upload to " + host, what);
          reportRequest(req);
        } catch (e) {
        }
      }
    });
  });
  const IMG_EXT = /\.(heic|heif|jpg|jpeg|png|webp|gif|avci|tiff?)$/i;
  const DRAIN_RETRIES = 30;
  _drainFiles = function() {
    if (!_pendingFiles.length) return;
    const job = _pendingFiles.shift();
    const path = job[0], label = job[1];
    const tries = job[2] + 1;
    const lastSize = job[3] || -1;
    _selfRead = true;
    const t0 = Date.now();
    try {
      const fm = frida_objc_bridge_default.classes.NSFileManager.defaultManager();
      let size = 0;
      try {
        const a = fm.attributesOfItemAtPath_error_(path, NULL);
        if (a) size = Number(a.objectForKey_("NSFileSize")) || 0;
      } catch (e) {
      }
      if (size === 0 || size !== lastSize) {
        if (tries < DRAIN_RETRIES) _pendingFiles.push([path, label, tries, size]);
        else emit(
          "MEDIA_FILE",
          label + " never settled",
          path.split("/").pop() + ", still changing after " + DRAIN_RETRIES + " checks"
        );
        return;
      }
      const name = path.split("/").pop();
      emit("MEDIA_FILE", label, name + ", " + size + " bytes");
      const url = frida_objc_bridge_default.classes.NSURL.fileURLWithPath_(path);
      if (IMG_EXT.test(path)) {
        const mk = dangerousExport("CGImageSourceCreateWithURL");
        const cp = dangerousExport("CGImageSourceCopyPropertiesAtIndex");
        if (mk && cp) {
          const fMk = new NativeFunction(mk, "pointer", ["pointer", "pointer"]);
          const fCp = new NativeFunction(
            cp,
            "pointer",
            ["pointer", "size_t", "pointer"]
          );
          const src = fMk(url.handle, NULL);
          if (!src.isNull()) {
            const props = fCp(src, 0, NULL);
            if (!props.isNull()) walkImageTags(new frida_objc_bridge_default.Object(props), label);
          }
        }
      } else {
        const asset = frida_objc_bridge_default.classes.AVURLAsset.URLAssetWithURL_options_(url, NULL);
        if (asset) {
          walkAVTags(asset.commonMetadata(), label + " common");
          walkAVTags(asset.metadata(), label + " format");
          try {
            const fmts = asset.availableMetadataFormats();
            const nf = fmts.count();
            for (let i = 0; i < nf; i++) {
              const f2 = fmts.objectAtIndex_(i);
              walkAVTags(asset.metadataForFormat_(f2), label + " " + String(f2));
            }
          } catch (e) {
          }
        }
      }
    } catch (e) {
      emit("MEDIA_FILE", label + " could not be read", String(e).slice(0, 80));
    } finally {
      _selfRead = false;
      const ms = Date.now() - t0;
      if (ms > 120) emit("RIG", "file parse was slow", ms + "ms");
    }
  };
  emit("RIG", "post-path hooks", mediaGot + " of " + mediaWanted + " attached");
  mediaMissed.forEach(function(m2) {
    emit("RIG", "post-path hook NOT attached", m2);
  });
  [
    ["UIAccessibilityIsAssistiveTouchRunning", "AssistiveTouch"],
    ["UIAccessibilityIsVoiceOverRunning", "VoiceOver"],
    ["UIAccessibilityIsSwitchControlRunning", "Switch Control"],
    ["UIAccessibilityIsGuidedAccessEnabled", "Guided Access"],
    ["UIAccessibilityIsBoldTextEnabled", "Bold Text"],
    ["UIAccessibilityIsReduceMotionEnabled", "Reduce Motion"],
    ["UIAccessibilityIsReduceTransparencyEnabled", "Reduce Transparency"],
    ["UIAccessibilityIsInvertColorsEnabled", "Invert Colors"],
    ["UIAccessibilityIsGrayscaleEnabled", "Grayscale"],
    ["UIAccessibilityDarkerSystemColorsEnabled", "Darker Colors"],
    ["UIAccessibilityIsShakeToUndoEnabled", "Shake to Undo"],
    ["UIAccessibilityIsMonoAudioEnabled", "Mono Audio"],
    ["UIAccessibilityIsClosedCaptioningEnabled", "Closed Captioning"],
    ["UIAccessibilityIsSpeakScreenEnabled", "Speak Screen"],
    ["UIAccessibilityIsVideoAutoplayEnabled", "Video Autoplay"]
  ].forEach(function(pair) {
    try {
      const p = Module.findGlobalExportByName(pair[0]);
      if (!p) return;
      hotHook(p, 6, "accessibility (" + pair[1] + ")", {
        onLeave: function(ret) {
          emit("A11Y", pair[1], ret.toInt32() ? "on" : "off");
        }
      });
    } catch (e) {
    }
  });
  try {
    const mg = Module.findGlobalExportByName("MGCopyAnswer");
    if (mg) {
      const b = budget(4e3, "MobileGestalt reads");
      Interceptor.attach(mg, {
        onEnter: function(args) {
          if (!b()) return;
          try {
            const key = new frida_objc_bridge_default.Object(args[0]).toString();
            if (key && key.length < 64) emit("GESTALT", key, null);
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.UIScreen && frida_objc_bridge_default.classes.UIScreen["- isCaptured"];
    if (m2) {
      hotHook(m2.implementation, 12, "isCaptured reads", {
        onLeave: function(ret) {
          emit(
            "CAPTURE",
            "screen recording or mirroring check",
            ret.toInt32() ? "currently captured" : "checked, not captured"
          );
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.UIScreen && frida_objc_bridge_default.classes.UIScreen["+ screens"];
    if (m2) {
      hotHook(m2.implementation, 12, "screens list reads", {
        onLeave: function(ret) {
          try {
            const n = ret.isNull() ? 0 : new frida_objc_bridge_default.Object(ret).count();
            emit(
              "CAPTURE",
              "external display check",
              n > 1 ? n + " screens attached" : "one screen"
            );
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.RPScreenRecorder && frida_objc_bridge_default.classes.RPScreenRecorder["- isRecording"];
    if (m2) {
      hotHook(m2.implementation, 12, "ReplayKit recording reads", {
        onLeave: function(ret) {
          emit(
            "CAPTURE",
            "ReplayKit recording check",
            ret.toInt32() ? "recording" : "not recording"
          );
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.GCController && frida_objc_bridge_default.classes.GCController["+ controllers"];
    if (m2) {
      hotHook(m2.implementation, 12, "controller reads", {
        onLeave: function(ret) {
          try {
            const n = ret.isNull() ? 0 : new frida_objc_bridge_default.Object(ret).count();
            emit("PERIPHERAL", "game controllers", n > 0 ? n + " attached" : "none");
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.GCKeyboard && frida_objc_bridge_default.classes.GCKeyboard["+ coalescedKeyboard"];
    if (m2) {
      hotHook(m2.implementation, 12, "keyboard reads", {
        onLeave: function(ret) {
          emit("PERIPHERAL", "hardware keyboard", ret.isNull() ? "none" : "attached");
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.GCMouse && frida_objc_bridge_default.classes.GCMouse["+ mice"];
    if (m2) {
      hotHook(m2.implementation, 12, "mouse reads", {
        onLeave: function(ret) {
          try {
            const n = ret.isNull() ? 0 : new frida_objc_bridge_default.Object(ret).count();
            emit("PERIPHERAL", "mouse", n > 0 ? n + " attached" : "none");
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.EAAccessoryManager && frida_objc_bridge_default.classes.EAAccessoryManager["- connectedAccessories"];
    if (m2) {
      hotHook(m2.implementation, 12, "accessory reads", {
        onLeave: function(ret) {
          try {
            const n = ret.isNull() ? 0 : new frida_objc_bridge_default.Object(ret).count();
            emit("PERIPHERAL", "MFi accessories", String(n));
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  [
    "- scanForPeripheralsWithServices:options:",
    "- retrieveConnectedPeripheralsWithServices:"
  ].forEach(function(sel2) {
    try {
      const m2 = frida_objc_bridge_default.classes.CBCentralManager && frida_objc_bridge_default.classes.CBCentralManager[sel2];
      if (!m2) return;
      Interceptor.attach(m2.implementation, {
        onEnter: function() {
          emit("PERIPHERAL", "Bluetooth", sel2.indexOf("scan") >= 0 ? "scanned for nearby BLE devices" : "listed connected BLE devices");
        }
      });
    } catch (e) {
    }
  });
  try {
    const m2 = frida_objc_bridge_default.classes.UIDevice && frida_objc_bridge_default.classes.UIDevice["- proximityState"];
    if (m2) {
      hotHook(m2.implementation, 12, "proximity reads", {
        onLeave: function(ret) {
          emit(
            "CONTEXT",
            "proximity sensor (phone at your face)",
            ret.toInt32() ? "covered" : "clear"
          );
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.UIDevice && frida_objc_bridge_default.classes.UIDevice["- orientation"];
    if (m2) {
      const ORI = [
        "unknown",
        "portrait",
        "portrait upside down",
        "landscape left",
        "landscape right",
        "face up",
        "face down"
      ];
      hotHook(m2.implementation, 12, "orientation reads", {
        onLeave: function(ret) {
          emit("CONTEXT", "device orientation", ORI[ret.toInt32()] || "read");
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.UIScreen && frida_objc_bridge_default.classes.UIScreen["- brightness"];
    if (m2) {
      hotHook(m2.implementation, 12, "brightness reads", {
        onEnter: function() {
          emit("CONTEXT", "screen brightness (ambient light proxy)", "read");
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.CHHapticEngine && frida_objc_bridge_default.classes.CHHapticEngine["+ capabilitiesForHardware"];
    if (m2) {
      Interceptor.attach(m2.implementation, {
        onEnter: function() {
          emit("CONTEXT", "haptic hardware class", "checked Taptic Engine capability");
        }
      });
    }
  } catch (e) {
  }
  try {
    const ge = Module.findGlobalExportByName("getenv");
    if (ge) {
      const b = budget(6e3, "getenv reads");
      const WATCH_ENV = /^(DYLD_INSERT_LIBRARIES|DYLD_|_MSSafeMode|SIMULATOR_)/;
      Interceptor.attach(ge, {
        onEnter: function(args) {
          this.n = b() ? cstr(args[0]) : null;
        },
        onLeave: function(ret) {
          if (this.n && WATCH_ENV.test(this.n)) {
            emit("INSTRUMENT", "read env " + this.n, ret.isNull() ? "unset" : "set");
          }
        }
      });
    }
  } catch (e) {
  }
  try {
    const p = Module.findGlobalExportByName("dlsym");
    if (p) {
      const b = budget(4e3, "dlsym reads");
      const WATCH_SYM = /MSHook|MSGetImage|substrate|substitute|frida|cynject|fishhook/i;
      Interceptor.attach(p, {
        onEnter: function(args) {
          this.s = b() ? cstr(args[1]) : null;
        },
        onLeave: function() {
          if (this.s && WATCH_SYM.test(this.s)) {
            emit("INSTRUMENT", "looked up hook symbol " + this.s, null);
          }
        }
      });
    }
  } catch (e) {
  }
  try {
    const p = Module.findGlobalExportByName("SecTaskCopyValueForEntitlement");
    if (p) {
      const b = budget(2e3, "entitlement reads");
      Interceptor.attach(p, {
        onEnter: function(args) {
          if (!b()) {
            this.k = null;
            return;
          }
          try {
            this.k = new frida_objc_bridge_default.Object(args[1]).toString();
          } catch (e) {
            this.k = null;
          }
        },
        onLeave: function() {
          if (this.k && this.k.length < 80) {
            emit("INSTRUMENT", "read entitlement " + this.k, null);
          }
        }
      });
    }
  } catch (e) {
  }
  {
    let bRadius = function(r) {
      if (!(r > 0)) return "zero, no contact patch (synthetic tell)";
      const a = Math.round(r / 5) * 5;
      if (r < 12) return "narrow, ~" + a + "pt";
      if (r < 28) return "finger-width, ~" + a + "pt";
      return "wide, ~" + a + "pt";
    }, bForce = function(f2) {
      if (!(f2 > 0)) return "zero (synthetic, or no force applied)";
      if (f2 < 1) return "light";
      if (f2 < 3) return "medium";
      return "firm";
    }, bCoalesced = function(n) {
      if (!(n > 0)) return "none (synthetic tell)";
      if (n <= 2) return String(n);
      return n + " (only real hardware fills these)";
    }, bSpeed = function(d) {
      if (d < 2) return "still";
      if (d < 15) return "slow";
      if (d < 40) return "medium";
      return "fast";
    };
    const TOUCHSRC = {
      1: "an indirect remote",
      2: "a stylus or Apple Pencil",
      3: "a mouse or trackpad pointer"
    };
    const PHASE = {
      0: "finger down",
      1: "moving",
      2: "held still",
      3: "lifted off",
      4: "cancelled"
    };
    try {
      const se = frida_objc_bridge_default.classes.UIApplication && frida_objc_bridge_default.classes.UIApplication["- sendEvent:"];
      if (se) {
        probe("touch", se.implementation, 20, "touch events (sendEvent)", {
          onEnter: function(args) {
            try {
              const ev = new frida_objc_bridge_default.Object(args[2]);
              let arr = null;
              try {
                const touches = ev.allTouches();
                if (touches && !touches.isNull() && Number(touches.count()) > 0) {
                  arr = touches.allObjects();
                }
              } catch (e) {
              }
              if (!arr) return;
              const t = arr.objectAtIndex_(0);
              let coalesced = -1;
              try {
                const c = ev.coalescedTouchesForTouch_(t);
                coalesced = c && !c.isNull() ? Number(c.count()) : 0;
              } catch (e) {
              }
              let tt = 0;
              try {
                tt = Number(t.type());
              } catch (e) {
              }
              let verdict;
              if (tt === 0) {
                verdict = coalesced > 0 ? "a real finger" : "a finger with no hardware sub-samples (synthetic / AssistiveTouch)";
              } else {
                verdict = TOUCHSRC[tt] || "input type " + tt;
              }
              emit("TOUCH", "what is driving the feed", verdict);
              try {
                const hid = ev._hidEvent();
                emit(
                  "TOUCH",
                  "came from the hardware digitizer",
                  hid && !hid.isNull() ? "yes, real hardware" : "no, it was synthesized"
                );
              } catch (e) {
              }
              if (coalesced >= 0) {
                emit("TOUCH", "hardware micro-samples this move", bCoalesced(coalesced));
              }
              try {
                emit("TOUCH", "fingertip contact width", bRadius(Number(t.majorRadius())));
              } catch (e) {
              }
              try {
                emit("TOUCH", "finger pressure", bForce(Number(t.force())));
              } catch (e) {
              }
              try {
                emit("TOUCH", "touch phase", PHASE[Number(t.phase())] || "phase");
              } catch (e) {
              }
              try {
                const loc = t.locationInView_(ptr(0));
                const prev = t.previousLocationInView_(ptr(0));
                const dx = loc.x - prev.x, dy = loc.y - prev.y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                emit("TOUCH", "swipe speed", bSpeed(dist));
                if (dist >= 2) {
                  emit(
                    "TOUCH",
                    "swipe direction",
                    Math.abs(dy) >= Math.abs(dx) ? dy > 0 ? "down" : "up" : dx > 0 ? "right" : "left"
                  );
                }
              } catch (e) {
              }
            } catch (e) {
            }
          }
        });
      }
    } catch (e) {
    }
  }
  {
    try {
      const m2 = frida_objc_bridge_default.classes.UIPanGestureRecognizer && frida_objc_bridge_default.classes.UIPanGestureRecognizer["- velocityInView:"];
      if (m2) {
        probe("touch", m2.implementation, 40, "scroll velocity reads", {
          onEnter: function() {
            emit("SCROLL", "your flick speed and direction", "measured as you scroll");
          }
        });
      }
    } catch (e) {
    }
  }
  ["- impactOccurred", "- impactOccurredWithIntensity:"].forEach(function(sel2) {
    try {
      const m2 = frida_objc_bridge_default.classes.UIImpactFeedbackGenerator && frida_objc_bridge_default.classes.UIImpactFeedbackGenerator[sel2];
      if (!m2) return;
      const b = budget(3e3, "impact haptics");
      Interceptor.attach(m2.implementation, {
        onEnter: function() {
          if (b()) emit("HAPTIC", "a buzz on tap or like", "played");
        }
      });
    } catch (e) {
    }
  });
  try {
    const m2 = frida_objc_bridge_default.classes.UINotificationFeedbackGenerator && frida_objc_bridge_default.classes.UINotificationFeedbackGenerator["- notificationOccurred:"];
    if (m2) {
      const b = budget(3e3, "notification haptics");
      const NT = ["success", "warning", "error"];
      Interceptor.attach(m2.implementation, {
        onEnter: function(args) {
          if (!b()) return;
          let t = -1;
          try {
            t = Number(args[2].toInt32());
          } catch (e) {
          }
          emit("HAPTIC", "a success or error buzz", NT[t] || "played");
        }
      });
    }
  } catch (e) {
  }
  try {
    const m2 = frida_objc_bridge_default.classes.UISelectionFeedbackGenerator && frida_objc_bridge_default.classes.UISelectionFeedbackGenerator["- selectionChanged"];
    if (m2) {
      const b = budget(3e3, "selection haptics");
      Interceptor.attach(m2.implementation, {
        onEnter: function() {
          if (b()) emit("HAPTIC", "a selection tick", "played");
        }
      });
    }
  } catch (e) {
  }
  {
    try {
      const m2 = frida_objc_bridge_default.classes.CMMotionManager && frida_objc_bridge_default.classes.CMMotionManager["- deviceMotion"];
      if (m2) {
        probe("touch", m2.implementation, 30, "device-motion value samples", {
          onLeave: function(ret) {
            try {
              if (ret.isNull()) return;
              const dm = new frida_objc_bridge_default.Object(ret);
              const att = dm.attitude();
              if (!att || att.isNull()) return;
              const roll = Math.round(att.roll() * 10) / 10;
              const pitch = Math.round(att.pitch() * 10) / 10;
              emit("SENSOR_VALUE", "hold angle (roll, pitch)", roll + ", " + pitch);
            } catch (e) {
            }
          }
        });
      }
    } catch (e) {
    }
  }
  ["- startDeviceMotionUpdatesToQueue:withHandler:", "- startDeviceMotionUpdates"].forEach(
    function(sel2) {
      try {
        const m2 = frida_objc_bridge_default.classes.CMHeadphoneMotionManager && frida_objc_bridge_default.classes.CMHeadphoneMotionManager[sel2];
        if (!m2) return;
        Interceptor.attach(m2.implementation, {
          onEnter: function() {
            emit("SENSOR", "AirPods head motion", "started collecting");
          }
        });
      } catch (e) {
      }
    }
  );
  emit("READY", "attached", null);
}
var _pubHits;
var PUB_DETACH_AFTER;
var TAG_VALUES;
var DEEP_BLOCKS;
