#include <lua.h>
#include <lauxlib.h>

#if LUA_VERSION_RELEASE_NUM != AIDA_LUA_ABI_RELEASE
#error Lua source release does not match the pinned AiDA Lua ABI
#endif

int aida_lua_abi_release(void) {
    return LUA_VERSION_RELEASE_NUM;
}

int aida_lua_registry_index(void) {
    return LUA_REGISTRYINDEX;
}

size_t aida_lua_number_sizes(void) {
    return LUAL_NUMSIZES;
}
