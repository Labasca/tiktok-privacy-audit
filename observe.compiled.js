📦
218507 /observe.js
147939 /observe.js.map
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
function eachExport(name) {
  const out = [];
  try {
    Process.enumerateModules().forEach(function(m2) {
      try {
        const p = m2.findExportByName && m2.findExportByName(name);
        if (p) out.push({ addr: p, mod: m2.name });
      } catch (e) {
      }
    });
  } catch (e) {
  }
  if (!out.length) {
    const p = dangerousExport(name);
    if (p) out.push({ addr: p, mod: "?" });
  }
  return out;
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
    try {
      if (!sa || sa.isNull()) return null;
      const family = sa.add(1).readU8();
      if (family === AF_INET) {
        const b = new Uint8Array(sa.add(4).readByteArray(4));
        return b.length === 4 ? b.join(".") : null;
      }
      if (family === AF_INET6) {
        const b = new Uint8Array(sa.add(8).readByteArray(16));
        if (b.length !== 16) return null;
        let scope = 0;
        try {
          scope = sa.add(24).readU32();
        } catch (e) {
        }
        if (b[0] === 254 && (b[1] & 192) === 128 && (b[2] || b[3])) {
          if (!scope) scope = b[2] << 8 | b[3];
          b[2] = 0;
          b[3] = 0;
        }
        const parts = [];
        for (let i = 0; i < 16; i += 2) parts.push(((b[i] << 8 | b[i + 1]) >>> 0).toString(16));
        return v6Canon(parts) + (scope ? "%" + scope : "");
      }
      return null;
    } catch (e) {
      return null;
    }
  }, v6Canon = function(parts) {
    let bestAt = -1, bestLen = 0, at = -1, len = 0;
    for (let i = 0; i < 8; i++) {
      if (parts[i] === "0") {
        if (at < 0) {
          at = i;
          len = 1;
        } else len++;
        if (len > bestLen) {
          bestLen = len;
          bestAt = at;
        }
      } else {
        at = -1;
        len = 0;
      }
    }
    if (bestLen < 2) return parts.join(":");
    const head = parts.slice(0, bestAt).join(":");
    const tail = parts.slice(bestAt + bestLen).join(":");
    return head + "::" + tail;
  }, readLinkAddr = function(sa) {
    try {
      if (!sa || sa.isNull() || sa.add(1).readU8() !== AF_LINK) return null;
      const nlen = sa.add(5).readU8(), alen = sa.add(6).readU8();
      if (alen < 1 || alen > 8) return null;
      const b = new Uint8Array(sa.add(8).add(nlen).readByteArray(alen));
      if (b.length !== alen) return null;
      const hex = [];
      for (let i = 0; i < b.length; i++) hex.push(("0" + b[i].toString(16)).slice(-2));
      return hex.join(":");
    } catch (e) {
      return null;
    }
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
  }, roundup = function(n) {
    return n ? n + 3 & ~3 : 4;
  }, isWildcard = function(a) {
    return a === "0.0.0.0" || a === "::" || a === "" || /^0(:0)*$/.test(a);
  }, reachEmit = function(name, value) {
    emit("REACH", name, value == null ? "available" : String(value).slice(0, 160));
  }, reachDenied = function(name, why) {
    emit("REACH_NO", name, why);
  }, routeDump = function(family, which, flags) {
    if (!_sysctlFn) return null;
    const mib = Memory.alloc(24);
    mib.writeU32(CTL_NET);
    mib.add(4).writeU32(PF_ROUTE);
    mib.add(8).writeU32(0);
    mib.add(12).writeU32(family);
    mib.add(16).writeU32(which);
    mib.add(20).writeU32(flags || 0);
    const lenp = Memory.alloc(8);
    lenp.writeULong(0);
    if (_sysctlFn(mib, 6, NULL, lenp, NULL, 0) !== 0) return null;
    let need = Number(lenp.readULong());
    if (need <= 0 || need > 4194304) return null;
    need = need + (need >> 2) + 4096;
    const buf = Memory.alloc(need);
    lenp.writeULong(need);
    if (_sysctlFn(mib, 6, buf, lenp, NULL, 0) !== 0) return null;
    return { buf, len: Number(lenp.readULong()) };
  }, walkRoutes = function(d, onEntry) {
    let off = 0, guard = 0, seen = 0;
    while (off + 92 <= d.len && guard++ < 4096) {
      const rec = d.buf.add(off);
      const msglen = rec.readU16();
      if (msglen < 92 || off + msglen > d.len) break;
      const flags = rec.add(8).readS32();
      const addrs = rec.add(12).readS32();
      let p = rec.add(92), dst = null, gw = null, gwSa = null;
      for (let bit = 0; bit < 8; bit++) {
        if (!(addrs & 1 << bit)) continue;
        const salen = p.readU8();
        if (bit === 0) dst = readSockaddr(p);
        if (bit === 1) {
          gw = readSockaddr(p);
          gwSa = p;
        }
        p = p.add(roundup(salen));
      }
      onEntry(flags, dst, gw, gwSa);
      seen++;
      off += msglen;
    }
    return seen;
  }, sweepGateway = function() {
    try {
      const d = routeDump(0, NET_RT_DUMP, 0);
      if (!d) {
        reachDenied("default gateway", "the route dump was refused");
        return;
      }
      let found = 0, rows = 0;
      rows = walkRoutes(d, function(flags, dst, gw) {
        if (flags & RTF_UP && flags & RTF_GATEWAY && dst !== null && isWildcard(dst) && gw) {
          reachEmit("default gateway", gw);
          found++;
        }
      });
      reachEmit("routing table size", rows + " routes readable");
      if (!found) reachEmit("default gateway", "no default route present");
    } catch (e) {
      reachDenied("default gateway", "read failed");
    }
  }, sweepNeighbours = function() {
    try {
      let total = 0;
      [[AF_INET, "IPv4"], [AF_INET6, "IPv6"]].forEach(function(fam) {
        const d = routeDump(fam[0], NET_RT_FLAGS, 1024);
        if (!d) return;
        walkRoutes(d, function(flags, dst, gw, gwSa) {
          if (!dst) return;
          const mac = readLinkAddr(gwSa);
          emit(
            "REACH_NEIGHBOUR",
            dst,
            mac && !/^0[02]:00:00:00:00:00$/.test(mac) ? mac : "IP readable, MAC masked by iOS"
          );
          total++;
        });
      });
      if (total) reachEmit("neighbour cache", total + " other devices on this network, by IP");
      else reachDenied("neighbour cache", "iOS returned no neighbours to this app");
    } catch (e) {
      reachDenied("neighbour cache", "read failed");
    }
  }, findLinkAddr = function(rec, msglen) {
    for (let o = 16; o + 8 <= msglen; o += 4) {
      try {
        const salen = rec.add(o).readU8(), fam = rec.add(o + 1).readU8();
        if (fam !== AF_LINK || salen < 8 || salen > 64 || o + salen > msglen) continue;
        const nlen = rec.add(o + 5).readU8(), alen = rec.add(o + 6).readU8();
        if (8 + nlen + alen > salen) continue;
        let name = "";
        if (nlen > 0 && nlen < 24) {
          const nb = new Uint8Array(rec.add(o + 8).readByteArray(nlen));
          for (let i = 0; i < nb.length; i++) name += String.fromCharCode(nb[i]);
        }
        return {
          name,
          mac: alen ? readLinkAddr(rec.add(o)) : null,
          index: rec.add(o + 2).readU16()
        };
      } catch (e) {
      }
    }
    return null;
  }, sweepInterfaceList = function() {
    try {
      const d = routeDump(0, NET_RT_IFLIST, 0);
      if (!d) {
        reachDenied("interface list via sysctl", "the dump was refused");
        return;
      }
      let off = 0, guard = 0, ifaces = 0;
      const byIndex = {};
      while (off + 4 <= d.len && guard++ < 4096) {
        const rec = d.buf.add(off);
        const msglen = rec.readU16();
        if (msglen < 4 || off + msglen > d.len) break;
        const type = rec.add(3).readU8();
        if (type === RTM_IFINFO || type === RTM_IFINFO2) {
          const li = findLinkAddr(rec, msglen);
          if (li && li.name) {
            byIndex[li.index] = li.name;
            ifaces++;
            const masked = !li.mac || /^0[02]:00:00:00:00:00$/.test(li.mac);
            emit(
              "REACH_IFACE",
              li.name,
              li.mac ? masked ? "hardware address masked by iOS" : li.mac : "no hardware address"
            );
          }
        } else if (type === RTM_NEWADDR) {
          const addrs = rec.add(4).readS32();
          const idx = rec.add(12).readU16();
          let p = rec.add(20), mask = null, addr = null;
          for (let bit = 0; bit < 8; bit++) {
            if (!(addrs & 1 << bit)) continue;
            const salen = p.readU8();
            if (bit === 2) mask = readSockaddr(p);
            if (bit === 5) addr = readSockaddr(p);
            p = p.add(roundup(salen));
          }
          if (addr) {
            emit(
              "REACH_IFADDR",
              (byIndex[idx] || "if" + idx) + "  " + addr,
              mask ? "netmask " + mask : "no netmask"
            );
          }
        }
        off += msglen;
      }
      reachEmit(
        "interface list via sysctl",
        ifaces + " interfaces, with names and hardware addresses"
      );
    } catch (e) {
      reachDenied("interface list via sysctl", "read failed");
    }
  }, cfStr = function(js) {
    try {
      return frida_objc_bridge_default.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String(js));
    } catch (e) {
      return null;
    }
  }, sweepWifiIdentity = function() {
    try {
      const p = Module.findGlobalExportByName("CNCopyCurrentNetworkInfo");
      if (!p) {
        reachDenied("Wi-Fi SSID and BSSID", "the API is not present");
        return;
      }
      const fn = new NativeFunction(p, "pointer", ["pointer"]);
      const nameStr = cfStr("en0");
      const ret = fn(nameStr ? nameStr.handle : NULL);
      if (ret.isNull()) {
        reachDenied(
          "Wi-Fi SSID and BSSID",
          "iOS refused it: this app is not entitled to Wi-Fi info"
        );
        return;
      }
      const d = new frida_objc_bridge_default.Object(ret);
      const ssid = d.objectForKey_("SSID"), bssid = d.objectForKey_("BSSID");
      if (ssid && !ssid.handle.isNull()) reachEmit("Wi-Fi network name", String(ssid));
      if (bssid && !bssid.handle.isNull()) reachEmit("Wi-Fi router address", String(bssid));
    } catch (e) {
      reachDenied("Wi-Fi SSID and BSSID", "read failed");
    }
    try {
      const p2 = Module.findGlobalExportByName("CNCopySupportedInterfaces");
      if (!p2) return;
      const fn2 = new NativeFunction(p2, "pointer", []);
      const ret2 = fn2();
      if (ret2.isNull()) {
        reachDenied("Wi-Fi interface list", "iOS returned nothing");
        return;
      }
      const arr = new frida_objc_bridge_default.Object(ret2);
      const names = [];
      for (let i = 0; i < Math.min(arr.count(), 8); i++) names.push(String(arr.objectAtIndex_(i)));
      reachEmit("Wi-Fi interface list", names.join(", "));
    } catch (e) {
    }
  }, sweepResolvers = function() {
    try {
      const p = Module.findGlobalExportByName("res_9_getservers");
      const init = Module.findGlobalExportByName("res_9_ninit");
      if (!p) {
        reachDenied("DNS servers", "the resolver API is not present");
        return;
      }
      const st = Memory.alloc(4096);
      if (init) {
        try {
          new NativeFunction(init, "int", ["pointer"])(st);
        } catch (e) {
        }
      }
      const set = Memory.alloc(128 * 8);
      const fn = new NativeFunction(p, "int", ["pointer", "pointer", "int"]);
      const n = fn(st, set, 8);
      if (n <= 0) {
        reachDenied("DNS servers", "the resolver returned none");
        return;
      }
      const out = [];
      for (let i = 0; i < Math.min(n, 8); i++) {
        const a = readSockaddr(set.add(i * 128));
        if (a) out.push(a);
      }
      if (out.length) reachEmit("DNS servers", out.join(", "));
      else reachDenied("DNS servers", "the resolver returned none");
    } catch (e) {
      reachDenied("DNS servers", "read failed");
    }
  }, sweepProxy = function() {
    try {
      const p = Module.findGlobalExportByName("CFNetworkCopySystemProxySettings");
      if (!p) return;
      const ret = new NativeFunction(p, "pointer", [])();
      if (ret.isNull()) {
        reachDenied("proxy settings", "iOS returned nothing");
        return;
      }
      const d = new frida_objc_bridge_default.Object(ret);
      const out = [];
      for (let i = 0; i < PROXY_KEYS.length; i++) {
        const v = d.objectForKey_(PROXY_KEYS[i]);
        if (v === null || v.handle.isNull()) continue;
        const sv = String(v);
        if (sv === "0") continue;
        out.push(PROXY_KEYS[i] + "=" + sv);
      }
      reachEmit("proxy settings", out.length ? out.join(" ") : "no proxy configured");
    } catch (e) {
    }
  }, sweepGestalt = function() {
    try {
      const mg = Module.findGlobalExportByName("MGCopyAnswer");
      if (!mg) return;
      const fn = new NativeFunction(mg, "pointer", ["pointer"]);
      GESTALT_WANTED.forEach(function(k) {
        try {
          const ks = cfStr(k);
          if (!ks) return;
          const ret = fn(ks.handle);
          if (ret.isNull()) {
            reachDenied("gestalt " + k, "iOS refused it");
            return;
          }
          reachEmit("gestalt " + k, String(new frida_objc_bridge_default.Object(ret)));
        } catch (e) {
          reachDenied("gestalt " + k, "read failed");
        }
      });
    } catch (e) {
    }
  }, wanQuery = function(urlStr, label, ephemeral) {
    try {
      const NSURL = frida_objc_bridge_default.classes.NSURL, NSURLSession = frida_objc_bridge_default.classes.NSURLSession;
      if (!NSURL || !NSURLSession) return;
      const url = NSURL.URLWithString_(urlStr);
      if (!url) return;
      let session;
      if (ephemeral && frida_objc_bridge_default.classes.NSURLSessionConfiguration) {
        const cfg = frida_objc_bridge_default.classes.NSURLSessionConfiguration.ephemeralSessionConfiguration();
        try {
          cfg.setTimeoutIntervalForRequest_(12);
        } catch (e) {
        }
        try {
          cfg.setTimeoutIntervalForResource_(18);
        } catch (e) {
        }
        session = NSURLSession.sessionWithConfiguration_(cfg);
      } else {
        session = NSURLSession.sharedSession();
      }
      const blk = new frida_objc_bridge_default.Block({
        retType: "void",
        argTypes: ["object", "object", "object"],
        implementation: function(data, resp, err) {
          try {
            if (err && !err.handle.isNull()) {
              let why = "";
              try {
                why = String(err.localizedDescription()) + " (code " + err.code() + ")";
              } catch (e) {
                why = "error with no description";
              }
              reachDenied(label, "the request failed: " + why);
              return;
            }
            if (!data || data.handle.isNull() || data.length() === 0) {
              let code2 = "";
              try {
                code2 = " (HTTP " + resp.statusCode() + ")";
              } catch (e) {
              }
              reachDenied(label, "the request returned an empty body" + code2);
              return;
            }
            const v = String(frida_objc_bridge_default.classes.NSString.alloc().initWithData_encoding_(data, 4)).trim();
            if (v && v.length < 46) emit("REACH_WAN", v, label);
            else reachDenied(label, "the reply was not an address");
          } catch (e) {
            reachDenied(label, "the reply could not be read");
          }
        }
      });
      _wanBlocks.push(blk);
      session.dataTaskWithURL_completionHandler_(url, blk).resume();
    } catch (e) {
      reachDenied(label, "the request could not be made");
    }
  }, wanRawSocket = function(ipStr, hostHdr, path, label) {
    let fd = -1;
    try {
      const g = Module.findGlobalExportByName.bind(Module);
      const _socket = new NativeFunction(g("socket"), "int", ["int", "int", "int"]);
      const _connect = new NativeFunction(g("connect"), "int", ["int", "pointer", "uint"]);
      const _send = new NativeFunction(g("send"), "long", ["int", "pointer", "ulong", "int"]);
      const _recv = new NativeFunction(g("recv"), "long", ["int", "pointer", "ulong", "int"]);
      const _close = new NativeFunction(g("close"), "int", ["int"]);
      const _setsockopt = new NativeFunction(
        g("setsockopt"),
        "int",
        ["int", "int", "int", "pointer", "uint"]
      );
      fd = _socket(2, 1, 0);
      if (fd < 0) {
        reachDenied(label, "no socket");
        return;
      }
      const tv = Memory.alloc(16);
      tv.writeU64(3);
      tv.add(8).writeU64(0);
      _setsockopt(fd, 65535, 4101, tv, 16);
      _setsockopt(fd, 65535, 4102, tv, 16);
      const sa = Memory.alloc(16);
      sa.writeU8(16);
      sa.add(1).writeU8(2);
      sa.add(2).writeU8(0);
      sa.add(3).writeU8(80);
      const parts = ipStr.split(".");
      for (let i = 0; i < 4; i++) sa.add(4 + i).writeU8(parseInt(parts[i], 10));
      if (_connect(fd, sa, 16) !== 0) {
        reachDenied(label, "could not connect to " + ipStr + " directly");
        _close(fd);
        return;
      }
      const req = "GET " + path + " HTTP/1.1\r\nHost: " + hostHdr + "\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n";
      const buf = Memory.allocUtf8String(req);
      if (_send(fd, buf, req.length, 0) < 0) {
        reachDenied(label, "the direct request could not be sent");
        _close(fd);
        return;
      }
      const rbuf = Memory.alloc(4096);
      const n = _recv(fd, rbuf, 4095, 0);
      _close(fd);
      fd = -1;
      if (n <= 0) {
        reachDenied(label, "no reply from " + ipStr);
        return;
      }
      const body = rbuf.readUtf8String(Number(n)) || "";
      const m2 = /(?:^|\n)ip=([0-9a-fA-F:.]{3,45})/.exec(body) || /\b(\d{1,3}(?:\.\d{1,3}){3})\b\s*$/.exec(body.trim());
      if (m2) emit("REACH_WAN", m2[1], label);
      else reachDenied(label, "the reply carried no address");
    } catch (e) {
      reachDenied(label, "the direct request failed");
      try {
        if (fd >= 0) new NativeFunction(
          Module.findGlobalExportByName("close"),
          "int",
          ["int"]
        )(fd);
      } catch (e2) {
      }
    }
  }, wanControl = function(urlStr, label) {
    try {
      const NSURL = frida_objc_bridge_default.classes.NSURL, NSURLSession = frida_objc_bridge_default.classes.NSURLSession;
      const url = NSURL.URLWithString_(urlStr);
      if (!url) return;
      const cfg = frida_objc_bridge_default.classes.NSURLSessionConfiguration.ephemeralSessionConfiguration();
      try {
        cfg.setTimeoutIntervalForRequest_(12);
      } catch (e) {
      }
      const blk = new frida_objc_bridge_default.Block({
        retType: "void",
        argTypes: ["object", "object", "object"],
        implementation: function(data, resp, err) {
          try {
            if (err && !err.handle.isNull()) {
              emit("REACH_PATH", label, "failed: " + String(err.localizedDescription()));
            } else {
              let code2 = "?";
              try {
                code2 = String(resp.statusCode());
              } catch (e) {
              }
              emit("REACH_PATH", label, "the request completed, HTTP " + code2);
            }
          } catch (e) {
          }
        }
      });
      _wanBlocks.push(blk);
      NSURLSession.sessionWithConfiguration_(cfg).dataTaskWithURL_completionHandler_(url, blk).resume();
    } catch (e) {
    }
  }, sweepWanDual = function() {
    wanQuery("https://api.ipify.org", "over IPv4, what a server sees", false);
    wanQuery("https://api64.ipify.org", "over whichever family it prefers", false);
    wanQuery("https://api.ipify.org", "over IPv4, on a fresh session", true);
    wanQuery("https://icanhazip.com", "a second provider, over TLS", true);
    wanQuery("https://1.1.1.1/cdn-cgi/trace", "to a numeric address, no lookup", true);
    wanControl("https://www.tiktok.com/robots.txt", "a TikTok host, same method");
    wanControl(
      "https://www.apple.com/library/test/success.html",
      "an unrelated host, same method"
    );
  }, sweepWanDirect = function() {
    wanRawSocket(
      "1.1.1.1",
      "1.1.1.1",
      "/cdn-cgi/trace",
      "a direct socket, no proxy settings consulted"
    );
  }, reachSweep = function(doWan) {
    const was = _selfRead;
    _selfRead = true;
    try {
      sweepGateway();
      sweepNeighbours();
      sweepResolvers();
      sweepProxy();
      sweepInterfaceList();
      sweepWifiIdentity();
      sweepGestalt();
      if (doWan) sweepWanDual();
    } catch (e) {
      emit("REACH_NO", "capability sweep", "aborted: " + e);
    } finally {
      _selfRead = was;
    }
    return true;
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
  }, resolverScan = function(buf, len) {
    try {
      if (len < 12) return;
      const head = buf.readU8();
      const isJson = head === 123 || head === 91;
      if (!isJson && len > 64) return;
      const n = len < 3072 ? len : 3072;
      const bytes = new Uint8Array(buf.readByteArray(n));
      let s = "";
      for (let i = 0; i < n; i++) {
        const ch = bytes[i];
        s += ch >= 32 && ch <= 126 ? String.fromCharCode(ch) : " ";
      }
      const bare = /^\s*(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{6,45})\s*$/.exec(s.slice(0, 64));
      if (bare && !seenResolverAnswer.has("wan" + bare[1])) {
        seenResolverAnswer.add("wan" + bare[1]);
        emit("REACH_WAN", bare[1], "seen in a reply, whatever asked for it");
      }
      if (s.indexOf('"cip"') < 0 && s.indexOf('"ips"') < 0) return;
      const cip = /"cip"\s*:\s*"([0-9a-fA-F:.]{3,45})"/.exec(s);
      if (cip && !seenResolverAnswer.has("cip" + cip[1])) {
        seenResolverAnswer.add("cip" + cip[1]);
        emit("PUBLIC_IP", cip[1], "echoed back by the resolver it asked");
      }
      const rec = /"host"\s*:\s*"([^"]{1,120})"[^}]*?"ips"\s*:\s*\[([^\]]{0,400})\]/g;
      let m2, guard = 0;
      while ((m2 = rec.exec(s)) !== null && guard++ < 24) {
        const host = m2[1];
        const ips = m2[2].replace(/"/g, "").split(",");
        for (let i = 0; i < ips.length && i < 16; i++) {
          const a = ips[i].trim();
          if (!a) continue;
          const tag = host + "|" + a;
          if (seenResolverAnswer.has(tag)) continue;
          seenResolverAnswer.add(tag);
          emit("HTTPDNS", host, a);
        }
      }
    } catch (e) {
    }
  }, makeResolverHandlers = function(secureTransport) {
    return {
      onEnter: function(args) {
        this.buf = args[1];
        this.got = secureTransport ? args[3] : null;
        this.st = secureTransport;
      },
      onLeave: function(retval) {
        try {
          if (this.buf.isNull()) return;
          let len;
          if (this.st) {
            if (retval.toInt32() !== 0 || this.got.isNull()) return;
            len = Number(this.got.readU64());
          } else {
            len = retval.toInt32();
          }
          if (len > 0) resolverScan(this.buf, len);
        } catch (e) {
        }
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
  const AF_INET = 2, AF_LINK = 18, AF_INET6 = 30;
  const IFF_UP = 1, IFF_LOOPBACK = 8, IFF_POINTOPOINT = 16;
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
          if (!name || !(flags & IFF_UP)) {
            cur = cur.readPointer();
            continue;
          }
          const ap = cur.add(24).readPointer();
          const addr = readSockaddr(ap);
          if (addr) {
            const tag = name + "|" + addr;
            if (!seenAddrs.has(tag)) {
              seenAddrs.add(tag);
              emit("INTERFACE", name, addr);
              const mask = readSockaddr(cur.add(32).readPointer());
              if (mask) emit("IFACE_MASK", name + " " + addr, mask);
            }
          } else {
            const mac = readLinkAddr(ap);
            if (mac) {
              const tag = name + "|hw|" + mac;
              if (!seenAddrs.has(tag)) {
                seenAddrs.add(tag);
                emit("IFACE_HW", name, mac);
              }
            }
          }
          if (flags & IFF_POINTOPOINT) {
            const peer = readSockaddr(cur.add(40).readPointer());
            if (peer) {
              const tag = name + "|peer|" + peer;
              if (!seenAddrs.has(tag)) {
                seenAddrs.add(tag);
                emit("IFACE_PEER", name, peer);
              }
            }
          }
          cur = cur.readPointer();
        }
      } catch (e) {
      }
    }
  });
  const seenEgress = /* @__PURE__ */ new Set();
  const EAI = {
    2: "temporary DNS failure",
    4: "permanent DNS failure",
    7: "name exists but has no address",
    8: "no such name",
    11: "system error",
    12: "bad hints"
  };
  const CONN_ERR = {
    36: "in progress",
    51: "network unreachable",
    65: "host unreachable",
    61: "refused",
    60: "timed out",
    56: "already connected",
    22: "rejected by the kernel"
  };
  const SOL_SOCKET = 65535, SO_TYPE = 4104;
  let sockType = function() {
    return null;
  };
  try {
    const gso = Module.findGlobalExportByName("getsockopt");
    if (gso) {
      const _gso = new NativeFunction(
        gso,
        "int",
        ["int", "int", "int", "pointer", "pointer"]
      );
      const tbuf = Memory.alloc(8), lbuf = Memory.alloc(4);
      sockType = function(fd) {
        try {
          lbuf.writeU32(4);
          if (_gso(fd, SOL_SOCKET, SO_TYPE, tbuf, lbuf) !== 0) return null;
          const t = tbuf.readU32();
          return t === 2 ? "UDP" : t === 1 ? "TCP" : null;
        } catch (e) {
          return null;
        }
      };
    }
  } catch (e) {
  }
  probe("net", dangerousExport("connect"), 120, "outbound connects", {
    onEnter: function(args) {
      this.sa = args[1];
      reportDest(args[1]);
      try {
        if (sockType(args[0].toInt32()) === "UDP") {
          const a = readSockaddr(args[1]);
          if (a) emit("SOCKTYPE", a, "UDP, so QUIC rather than TLS");
        }
      } catch (e) {
      }
    },
    onLeave: function(retval) {
      try {
        if (retval.toInt32() === 0) return;
        const e = this.errno;
        if (e === 36) return;
        const addr = readSockaddr(this.sa);
        if (addr) emit("CONNECT_FAIL", addr, CONN_ERR[e] || "errno " + e);
      } catch (e2) {
      }
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
      this.numeric = false;
      try {
        if (!args[2].isNull()) this.numeric = !!(args[2].readU32() & 4);
      } catch (e) {
      }
    },
    onLeave: function(retval) {
      try {
        if (!this.host) return;
        if (retval.toInt32() !== 0) {
          const code2 = retval.toInt32();
          const why = EAI[code2] || "error " + code2;
          emit(
            "DNS_FAIL",
            this.host,
            this.numeric ? "not a literal address (" + why + ")" : why
          );
          return;
        }
        if (this.numeric) emit("DNS_NUMERIC", this.host, "confirmed as a literal address");
        if (this.res.isNull()) return;
        let ai = this.res.readPointer();
        let guard = 0;
        const seen = /* @__PURE__ */ new Set();
        while (!ai.isNull() && guard++ < 32) {
          const addr = readSockaddr(ai.add(32).readPointer());
          if (addr && !seen.has(addr)) {
            seen.add(addr);
            emit("DNS", this.host, addr);
          }
          const cn = ai.add(24).readPointer();
          if (!cn.isNull()) {
            const canon = cstr(cn);
            if (canon && canon !== this.host) emit("DNS_CNAME", this.host, canon);
          }
          ai = ai.add(40).readPointer();
        }
      } catch (e) {
      }
    }
  });
  probe("net", dangerousExport("getnameinfo"), 60, "reverse lookups", {
    onEnter: function(args) {
      this.sa = args[0];
      this.hostbuf = args[2];
    },
    onLeave: function(retval) {
      try {
        if (retval.toInt32() !== 0 || this.hostbuf.isNull()) return;
        const addr = readSockaddr(this.sa), name = cstr(this.hostbuf);
        if (addr && name) emit("DNS_REVERSE", addr, name);
      } catch (e) {
      }
    }
  });
  ["gethostbyname", "gethostbyname2"].forEach(function(sym) {
    probe("net", dangerousExport(sym), 60, "legacy name lookups", {
      onEnter: function(args) {
        this.host = args[0].isNull() ? null : cstr(args[0]);
      },
      onLeave: function(retval) {
        try {
          if (!this.host || retval.isNull()) return;
          const len = retval.add(20).readS32();
          if (len !== 4 && len !== 16) return;
          let listp = retval.add(24).readPointer(), guard = 0;
          while (!listp.isNull() && guard++ < 16) {
            const ap = listp.readPointer();
            if (ap.isNull()) break;
            const b = new Uint8Array(ap.readByteArray(len));
            if (b.length === 4) emit("DNS", this.host, b.join("."));
            listp = listp.add(8);
          }
        } catch (e) {
        }
      }
    });
  });
  probe("net", dangerousExport("nw_endpoint_get_hostname"), 150, "nw endpoint names", {
    onLeave: function(retval) {
      try {
        if (retval.isNull()) return;
        const h = cstr(retval);
        if (h) emit("NW_ENDPOINT", h, "name");
      } catch (e) {
      }
    }
  });
  probe(
    "net",
    dangerousExport("nw_endpoint_copy_address_string"),
    150,
    "nw endpoint addresses",
    {
      onLeave: function(retval) {
        try {
          if (retval.isNull()) return;
          const a = retval.readUtf8String();
          if (a) emit("NW_ENDPOINT", a, "address");
        } catch (e) {
        }
      }
    }
  );
  probe("net", dangerousExport("sendto"), 60, "datagrams sent", {
    onEnter: function(args) {
      try {
        const addr = readSockaddr(args[4]);
        if (addr && !isUnspecified(addr)) {
          emit("UDP_PEER", addr, String(readPort(args[4])));
        }
      } catch (e) {
      }
    }
  });
  probe("net", dangerousExport("recvfrom"), 60, "datagrams received", {
    onEnter: function(args) {
      this.from = args[4];
    },
    onLeave: function(retval) {
      try {
        if (retval.toInt32() < 0 || this.from.isNull()) return;
        const addr = readSockaddr(this.from);
        if (addr && !isUnspecified(addr)) {
          emit("UDP_PEER", addr, String(readPort(this.from)));
        }
      } catch (e) {
      }
    }
  });
  probe("net", dangerousExport("getpeername"), 120, "peer address reads", {
    onEnter: function(args) {
      this.sa = args[1];
    },
    onLeave: function(retval) {
      try {
        if (retval.toInt32() !== 0 || this.sa.isNull()) return;
        const addr = readSockaddr(this.sa);
        if (addr && !isUnspecified(addr)) {
          emit("PEER", addr, String(readPort(this.sa)));
        }
      } catch (e) {
      }
    }
  });
  probe("net", dangerousExport("SSLSetPeerDomainName"), 120, "TLS SNI (Secure Transport)", {
    onEnter: function(args) {
      try {
        const n = args[2].toInt32();
        if (n > 0 && n < 256) {
          const h = args[1].readUtf8String(n);
          if (h) emit("SNI", h, null);
        }
      } catch (e) {
      }
    }
  });
  eachExport("SSL_set_tlsext_host_name").forEach(function(ex) {
    probe("net", ex.addr, 120, "TLS SNI (BoringSSL in " + ex.mod + ")", {
      onEnter: function(args) {
        try {
          if (args[1].isNull()) return;
          const h = cstr(args[1]);
          if (h) emit("SNI", h, null);
        } catch (e) {
        }
      }
    });
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
  const CTL_NET = 4, PF_ROUTE = 17;
  const NET_RT_DUMP = 1, NET_RT_FLAGS = 2, NET_RT_IFLIST = 3, NET_RT_IFLIST2 = 6;
  const RTF_UP = 1, RTF_GATEWAY = 2;
  const RT_WHICH = {};
  RT_WHICH[NET_RT_DUMP] = "routing table";
  RT_WHICH[NET_RT_FLAGS] = "neighbour cache";
  RT_WHICH[NET_RT_IFLIST] = "interface list";
  RT_WHICH[NET_RT_IFLIST2] = "interface list";
  try {
    const sysctlp = Module.findGlobalExportByName("sysctl");
    if (sysctlp) {
      const routeBudget = budget(24, "routing table dumps");
      Interceptor.attach(sysctlp, {
        onEnter: function(args) {
          this.route = false;
          if (_selfRead) return;
          try {
            if (args[1].toInt32() < 6) return;
            const mib = args[0];
            if (mib.readU32() !== CTL_NET || mib.add(4).readU32() !== PF_ROUTE) return;
            this.route = true;
            this.which = mib.add(16).readU32();
            this.oldp = args[2];
            this.oldlenp = args[3];
          } catch (e) {
            this.route = false;
          }
        },
        onLeave: function(retval) {
          try {
            if (!this.route) return;
            emit("ROUTE", "read the " + (RT_WHICH[this.which] || "route table"), null);
            if (retval.toInt32() !== 0 || this.oldp.isNull() || this.oldlenp.isNull()) return;
            if (!routeBudget()) return;
            const total = this.oldlenp.readULong();
            let off = 0, guard = 0;
            while (off + 92 <= total && guard++ < 512) {
              const rec = this.oldp.add(off);
              const msglen = rec.readU16();
              if (msglen < 92 || off + msglen > total) break;
              const flags = rec.add(8).readS32();
              const addrs = rec.add(12).readS32();
              let p = rec.add(92), dst = null, gw = null, gwSa = null;
              for (let bit = 0; bit < 8; bit++) {
                if (!(addrs & 1 << bit)) continue;
                const salen = p.readU8();
                if (bit === 0) dst = readSockaddr(p);
                if (bit === 1) {
                  gw = readSockaddr(p);
                  gwSa = p;
                }
                p = p.add(roundup(salen));
              }
              if (flags & RTF_UP && flags & RTF_GATEWAY && dst !== null && isWildcard(dst) && gw) {
                emit("ROUTE", "default gateway", gw);
              } else if (this.which === NET_RT_FLAGS && dst && gwSa) {
                const mac = readLinkAddr(gwSa);
                if (mac) emit("NEIGHBOUR", dst, mac);
              }
              off += msglen;
            }
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  let _sysctlFn = null;
  try {
    const sp = Module.findGlobalExportByName("sysctl");
    if (sp) {
      _sysctlFn = new NativeFunction(
        sp,
        "int",
        ["pointer", "uint", "pointer", "pointer", "pointer", "ulong"]
      );
    }
  } catch (e) {
  }
  const RTM_IFINFO = 14, RTM_IFINFO2 = 18, RTM_NEWADDR = 12;
  const GESTALT_WANTED = [
    "RegionCode",
    "RegionInfo",
    "DeviceName",
    "ProductType",
    "ReleaseType",
    "InternationalMobileEquipmentIdentity",
    "SerialNumber",
    "UniqueDeviceID",
    "WifiAddress",
    "BluetoothAddress"
  ];
  const _wanBlocks = [];
  rpc.exports.reachwan = function() {
    const was = _selfRead;
    _selfRead = true;
    try {
      sweepWanDirect();
    } finally {
      _selfRead = was;
    }
    return true;
  };
  rpc.exports.reach = function(doWan) {
    return reachSweep(!!doWan);
  };
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
    const rgs = Module.findGlobalExportByName("res_9_getservers");
    if (rgs) {
      const rgsBudget = budget(64, "resolver list reads");
      Interceptor.attach(rgs, {
        onEnter: function(args) {
          this.set = args[1];
          this.cnt = args[2].toInt32();
        },
        onLeave: function(retval) {
          try {
            if (_selfRead || !rgsBudget()) return;
            emit("RESOLVER", "resolver list", null);
            let n = retval.toInt32();
            if (n < 0 || this.set.isNull()) return;
            if (n > this.cnt) n = this.cnt;
            if (n > 8) n = 8;
            for (let i = 0; i < n; i++) {
              const a = readSockaddr(this.set.add(i * 128));
              if (a) emit("RESOLVER", "DNS server", a);
            }
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  try {
    const scr = Module.findGlobalExportByName("SCNetworkReachabilityGetFlags");
    if (scr) {
      const scrBudget = budget(200, "reachability checks");
      const REACH = [
        [1, "transient"],
        [2, "reachable"],
        [4, "connection required"],
        [8, "connects automatically"],
        [16, "connects on demand"],
        [32, "is local address"],
        [64, "is direct"],
        [262144, "over cellular"]
      ];
      Interceptor.attach(scr, {
        onEnter: function(args) {
          this.flags = args[1];
        },
        onLeave: function(retval) {
          try {
            if (!scrBudget()) return;
            emit("DISPLAY", "connection reachability", "via SystemConfiguration");
            if (!retval.toInt32() || this.flags.isNull()) return;
            const f2 = this.flags.readU32();
            for (let i = 0; i < REACH.length; i++) {
              if (f2 & REACH[i][0]) emit("NWPATH", REACH[i][1], "yes");
            }
          } catch (e) {
          }
        }
      });
    }
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
        onEnter: function(args) {
          if (!_selfRead) {
            emit("INTERFACE_ID", "Wi-Fi network identity", "asked for SSID and BSSID");
          }
          this.iface = args[0].isNull() ? null : String(new frida_objc_bridge_default.Object(args[0]));
        },
        onLeave: function(retval) {
          try {
            if (_selfRead) return;
            if (retval.isNull()) {
              emit(
                "INTERFACE_ID",
                "Wi-Fi network identity answer",
                "iOS returned nothing, the app is not entitled to it"
              );
              return;
            }
            const d = new frida_objc_bridge_default.Object(retval);
            if (this.iface) emit("INTERFACE_ID", "asked about interface", this.iface);
            const ssid = d.objectForKey_("SSID");
            const bssid = d.objectForKey_("BSSID");
            if (ssid && !ssid.handle.isNull()) {
              emit("INTERFACE_ID", "Wi-Fi network name", String(ssid));
            }
            if (bssid && !bssid.handle.isNull()) {
              emit("INTERFACE_ID", "Wi-Fi router address", String(bssid));
            }
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  try {
    const csi = Module.findGlobalExportByName("CNCopySupportedInterfaces");
    if (csi) {
      const csiBudget = budget(32, "Wi-Fi interface list reads");
      Interceptor.attach(csi, {
        onLeave: function(retval) {
          try {
            if (_selfRead || !csiBudget() || retval.isNull()) return;
            const arr = new frida_objc_bridge_default.Object(retval);
            const n = Math.min(arr.count(), 8);
            for (let i = 0; i < n; i++) {
              emit("INTERFACE_ID", "Wi-Fi interface", String(arr.objectAtIndex_(i)));
            }
          } catch (e) {
          }
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
    eachExport(nm).forEach(function(e) {
      probe(
        "tls",
        e.addr,
        60,
        "TLS write (" + nm + " in " + e.mod + ")",
        { onEnter: tlsWriteHandler }
      );
    });
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
  eachExport("SSLRead").forEach(function(e) {
    probe(
      "tls",
      e.addr,
      60,
      "TLS read (SSLRead in " + e.mod + ")",
      makeReadHandlers(true)
    );
  });
  eachExport("SSL_read").forEach(function(e) {
    probe(
      "tls",
      e.addr,
      60,
      "TLS read (SSL_read in " + e.mod + ")",
      makeReadHandlers(false)
    );
  });
  const seenResolverAnswer = /* @__PURE__ */ new Set();
  eachExport("SSL_read").forEach(function(e) {
    probe(
      "net",
      e.addr,
      1500,
      "resolver answers (SSL_read in " + e.mod + ")",
      makeResolverHandlers(false)
    );
  });
  eachExport("SSLRead").forEach(function(e) {
    probe(
      "net",
      e.addr,
      1500,
      "resolver answers (SSLRead in " + e.mod + ")",
      makeResolverHandlers(true)
    );
  });
  const PROXY_KEYS = [
    "HTTPEnable",
    "HTTPProxy",
    "HTTPPort",
    "HTTPSEnable",
    "HTTPSProxy",
    "HTTPSPort",
    "SOCKSEnable",
    "SOCKSProxy",
    "SOCKSPort",
    "ProxyAutoConfigEnable",
    "ProxyAutoConfigURLString"
  ];
  try {
    const proxy = Module.findGlobalExportByName("CFNetworkCopySystemProxySettings");
    if (proxy) {
      const proxyBudget = budget(64, "proxy config reads");
      Interceptor.attach(proxy, {
        onEnter: function() {
          if (!_selfRead) emit("PROXY", "proxy config", null);
        },
        onLeave: function(retval) {
          try {
            if (_selfRead || !proxyBudget() || retval.isNull()) return;
            const d = new frida_objc_bridge_default.Object(retval);
            let set = 0;
            for (let i = 0; i < PROXY_KEYS.length; i++) {
              const k = PROXY_KEYS[i];
              const v = d.objectForKey_(k);
              if (v === null || v.handle.isNull()) continue;
              const s = String(v);
              if (s === "0") continue;
              set++;
              emit("PROXY", "proxy " + k, s);
            }
            if (!set) emit("PROXY", "proxy answer", "no proxy configured");
          } catch (e) {
          }
        }
      });
    }
  } catch (e) {
  }
  try {
    const NEVPNManager = frida_objc_bridge_default.classes.NEVPNManager;
    if (NEVPNManager && NEVPNManager["- connection"]) {
      const VPN_STATUS = [
        "no VPN configured for this app",
        "disconnected",
        "connecting",
        "connected",
        "reasserting",
        "disconnecting"
      ];
      Interceptor.attach(NEVPNManager["- connection"].implementation, {
        onEnter: function() {
          emit("PROXY", "VPN status", null);
        },
        onLeave: function(retval) {
          try {
            if (retval.isNull()) return;
            const st = new frida_objc_bridge_default.Object(retval).status();
            emit("PROXY", "VPN status answer", VPN_STATUS[st] || "status " + st);
          } catch (e) {
          }
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
          if (_selfRead || !b()) return;
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

✄
{
  "version": 3,
  "sources": ["node_modules/frida-objc-bridge/lib/api.js", "node_modules/frida-objc-bridge/lib/fastpaths.js", "node_modules/frida-objc-bridge/index.js", "observe.js"],
  "mappings": "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",
  "names": ["api", "signature", "pointerSize", "method", "sel", "handle", "superSpecifier", "methodHandle", "types", "protocol", "m", "ptr", "block", "signature", "selector", "key", "name", "implementation", "owner", "invocationOptions", "retType", "argTypes", "m", "ptr", "code", "sel", "method", "s", "f"]
}
