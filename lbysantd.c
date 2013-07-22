#include "lua.h"
#include "lauxlib.h"
#include "bysantd.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>



// TODO This now seems to work.
// deserialize returns the metrics table followed by the deserilized table followed by the offset of the next element to deserilize in the stream.

#define CKSTACK(L, x) luaL_checkstack( L, x, "M3DA Bysant deserializer")

//store shortcut in reference system, containing niltoken, set at init
static int niltoken_reg = 0;
//push onto the stack the niltoken set at init
static void push_niltoken(lua_State *L){
    lua_rawgeti(L, LUA_REGISTRYINDEX, niltoken_reg);
}


static void insertmetrics(lua_State *L, int tableidx, int offset, int length) {
    lua_createtable( L, 0, 2);
    lua_pushinteger(L, offset);
    lua_setfield(L, -2, "offset");
    lua_pushinteger(L, length);
    lua_setfield(L, -2, "length");
    lua_insert(L, tableidx);
}

static void mergemetricstables(lua_State *L, int t1, int t2)
{
    lua_getfield(L, t1, "length");
    int l1 = lua_tointeger(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, t2, "length");
    int l2 = lua_tointeger(L, -1);
    lua_pop(L, 1);

    lua_getfield(L, t1, "offset");
    lua_setfield(L, t2, "offset");
    lua_pushnumber(L, l1+l2);
    lua_setfield(L, t2, "length");
}

static int bysant2lua( lua_State *L, const bsd_data_t *x, int offset, int length) {
    /* This buffer will be used to efficiently concatenate chunked strings. Since objects are
     * guaranted to be only chunks (or errors), there is no stack manipulation problem.
     * Instead of allocating as global, it is allocated as userdata when needed. */
    //FIXME: this assume that the function is always called with the same lua_State.
    static luaL_Buffer *buf;

    CKSTACK( L, 1); /* at least one object will be pushed */

    int metricidx = -2; //default number of element on the stack for the deserialized object
    
    /* step 1: the object is pushed on stack */
    switch( x->type) {
    /* pushnumber is used instead of pushinteger because of possible overflows:
     * lua_Integer is likely defined as ptrdiff_t which is a 32 bit integer. */
    case BSD_INT:     lua_pushnumber( L, x->content.i);     break;
    case BSD_NULL:    push_niltoken( L);                    break; //handle M3DA null coming from server
    case BSD_BOOL:    lua_pushboolean( L, x->content.bool); break;
    case BSD_DOUBLE:  lua_pushnumber( L, x->content.d);     break;
    case BSD_STRING:  lua_pushlstring( L, x->content.string.data, x->content.string.length); break;
    case BSD_CHUNK:   luaL_addlstring( buf, x->content.chunk.data, x->content.chunk.length); break;

    case BSD_MAP: case BSD_ZMAP: {
        int len = BSD_ZMAP==x->type ? 0 : x->content.length;
        lua_createtable( L, 0, len); // table
        break;
    }

    /* The index of the last object inserted in the Lua list is kept at
     * stack index -2. */
    case BSD_LIST: case BSD_ZLIST: {
        int len = BSD_ZLIST==x->type ? 0 : x->content.length;
        CKSTACK( L, 3);
        lua_pushinteger( L, 0);      //  idx
        lua_createtable( L, len, 0); //  idx, table
        metricidx = -3;
        break;
    }

    case BSD_OBJECT:
        /* If the class is named, fields will be named rather than numbered;
         * the class table will then be used as a list.
         * `idx` is the index of the last inserted field in tables used as lists.
         * Even for named classes, a dummy `idx` is inserted to save a test
         * when closing. */
        CKSTACK( L, 4);
        lua_pushinteger( L, 0);                                       //  idx
        if( NULL == x->content.classdef->classname) {
            lua_createtable( L, x->content.classdef->nfields, 1);     //  idx, table
            lua_pushinteger( L, x->content.classdef->classid);        //  idx, table, classid
        } else { /* named class */
            lua_createtable( L, 0, x->content.classdef->nfields + 1); //  idx, table
            lua_pushstring( L, x->content.classdef->classname);       //  idx, table, classname
        }
        lua_setfield( L, -2, "__class");           //  idx, table[__class=classid or classname]
        metricidx = -3;
        break;

    case BSD_CHUNKED_STRING:
        buf = lua_newuserdata( L, sizeof(luaL_Buffer)); // buffer
        luaL_buffinit( L, buf);
        break;

    case BSD_CLOSE:
        switch( x->content.cont_type) {
        case BSD_CHUNKED_STRING:   // buffer
            luaL_pushresult( buf); // buffer, result_string
            lua_replace( L, -2);   // result_string
            break;
        case BSD_OBJECT: case BSD_LIST: case BSD_ZLIST: // idx, table
            lua_replace( L, -2); // table
            break;
        default: break; // including MAP and ZMAP
        }
        // Compute and set the length field
                                            // metrics, table
        lua_getfield(L, -2, "offset");      // metrics, table, offset
        lua_Integer startoffset = lua_tointeger(L, -1);
        lua_pop(L, 1);                      // metrics table
        length = offset+length-startoffset;
        lua_pushinteger(L, length);         // metrics, table, length
        lua_setfield(L, -3, "length");      // metrics, table
        break;

    case BSD_ERROR:
        switch( x->content.error) {
#        define CASE(x) case BSD_E##x: lua_pushstring( L, #x); break
        CASE( NOTIMPL);
        CASE( INVALID);
        CASE( BADCONTEXT);
        CASE( INVOPCODE);
        CASE( BADCLASSID);
        CASE( TOODEEP);
        CASE( INTERNAL);
#        undef CASE
        default: break;
        }
        //printf("bysant: reinitializing ctx due to error\n");
        return -1;

    case BSD_CLASSDEF: return 0; // nothing to do

    default:
        lua_pushfstring( L, "Unhandled type: %d", x->type);
        return -1;
    }

    CKSTACK( L, 1);

    // Add the metrics table
    if (x->type != BSD_CLOSE && x->type != BSD_CHUNK)
    {
        insertmetrics(L, metricidx, offset, length);
    }

    // For the case of strings, we need to add more information on the string tag size
    if (x->type == BSD_STRING || x->type == BSD_CHUNK || x->type == BSD_CHUNKED_STRING)
    {
        // create the sub offset table
        if (x->type != BSD_CHUNK)
        {
            lua_newtable(L);
            lua_setfield(L, metricidx-1, "suboffsets");
        }
        // add a [offset]=delta in the suboffset table
        if(x->type == BSD_STRING || x->type == BSD_CHUNK)
        {
            int v = x->type == BSD_STRING ? x->content.string.length : x->content.chunk.length;
            lua_getfield(L, metricidx, "suboffsets");
            lua_pushfstring(L, "%d:%d", offset, length-v);
            int i = lua_objlen(L, -2); i = i==0?1:i;
            lua_rawseti(L, -2, i);
            lua_pop(L, 1);
        }
    }

    // The elements on the stack are prefixed with a metrics table

    /* Step 2: the object is inserted in its container */
    switch( x->kind) {
    case BSD_KTOPLEVEL: break;
    case BSD_KOBJFIELD: // objmetrics, idx, obj, valuemetrics, value
        if( NULL != x->fieldname) { /* if field is named, set it with textual key */
            lua_setfield( L, -3, x->fieldname); // objmetrics, idx, obj[fieldname]=value valuemetrics
            lua_setfield( L, -4, x->fieldname); // objmetrics[fieldname]=valuemetrics idx obj[fieldname]=value   => objmetrics idx obj
            break;
        }
        /* otherwise, apply the same as list */
        /* fall through. */      
    case BSD_KLISTITEM: // listmetrics, idx, table, valuemetrics, value
        CKSTACK( L, 2);
        int new_idx = lua_tointeger( L, -4) + 1;
        lua_pushinteger( L, new_idx); // listmetrics, idx, table, valuemetrics, value, idx+1
        lua_pushvalue(   L, -1);      // listmetrics, idx, table, valuemetrics, value, idx+1, idx+1
        lua_replace(     L, -6);      // listmetrics, idx+1, table, valuemetrics, value, idx+1
        lua_insert(      L, -2);      // listmetrics, idx+1, table, valuemetrics, idx+1, value
        lua_settable(    L, -4);      // listmetrics, idx+1, table, valuemetrics
        lua_pushvalue(   L, -3);      // listmetrics, idx+1, table, valuemetrics, idx+1
        lua_insert(      L, -2);      // listmetrics, idx+1, table, idx+1, valuemetrics
        lua_settable(    L, -5);      // listmetrics, idx+1, table
        break;
    case BSD_KMAPVALUE:       // tablemetrics, table, keymetrics, key, valuemetrics, value
        lua_pushvalue(L, -3); // tablemetrics, table, keymetrics, key, valuemetrics, value, key
        lua_insert(L, -2);    // tablemetrics, table, keymetrics, key, valuemetrics, key, value
        lua_settable( L, -6); // tablemetrics, table, keymetrics, key, valuemetrics
        int top = lua_gettop(L)+1;
        mergemetricstables(L, top-3, top-1);
        lua_settable( L, -5); // tablemetrics, table, keymetrics,
        lua_pop(L, 1);        // tablemetrics, table
        
        break;
    case BSD_KMAPKEY: // wait for associated value
    case BSD_KCHUNK:
    case BSD_KNEWCONTAINER: break;
    }
    return 0; // success
}


struct bs_field_t penv [] =
{
    { .name="header",  .ctxid=6 },
    { .name="payload", .ctxid=1 },
    { .name="footer",  .ctxid=6 },
            
};
struct bs_field_t pmes [] =
{
    { .name="path",  .ctxid=1 },
    { .name="ticketid", .ctxid=1 },
    { .name="body",  .ctxid=6 },
};
struct bs_field_t pres [] =
{
    { .name="ticketid",  .ctxid=1 },
    { .name="status", .ctxid=2 },
    { .name="data",  .ctxid=1 },
};
struct bs_field_t pdv [] =
{
    { .name="factor",  .ctxid=2 },
    { .name="start", .ctxid=2 },
    { .name="deltas",  .ctxid=6 },
};
struct bs_field_t pqp [] =
{
    { .name="period",  .ctxid=2 },
    { .name="start", .ctxid=2 },
    { .name="shifts",  .ctxid=6 },
};

const bs_class_t m3da_classes[] =
    {
        {
            .classid = 0,
            .classname = "Envelope",
            .nfields = 3,
            .mode = BS_CLASS_EXTERNAL,
            .fields = penv,
        },
        {
            .classid = 1,
            .classname = "Message",
            .nfields = 3,
            .mode = BS_CLASS_EXTERNAL,
            .fields = pmes,
        },
        {
            .classid = 2,
            .classname = "Response",
            .nfields = 3,
            .mode = BS_CLASS_EXTERNAL,
            .fields = pres,
        },
        {
            .classid = 3,
            .classname = "DeltasVector",
            .nfields = 3,
            .mode = BS_CLASS_EXTERNAL,
            .fields = pdv,
        },
        {
            .classid = 4,
            .classname = "QuasiPeriodicVector",
            .nfields = 3,
            .mode = BS_CLASS_EXTERNAL,
            .fields = pqp,
        },
    };

    
static addm3daclassdef(bsd_ctx_t *ctx)
{

    int i;
    for  (i=0; i<sizeof(m3da_classes)/sizeof(*m3da_classes); i++)
    {
        bsd_addClass(ctx, &m3da_classes[i]);
    }
};


// Deserialize next object
// input: string to deserialize, optional offset in that string
// ouput: metrics, object, consumed bytes
static int api_deserialize( lua_State *L)
{

    size_t bufferlen;
    const uint8_t *buffer = (const uint8_t *)luaL_checklstring (L, 1, &bufferlen);
    int offset = luaL_optint (L, 2, 0);
    bsd_data_t data;
    bsd_ctx_t *ctx = (bsd_ctx_t *) lua_newuserdata( L, sizeof( bsd_ctx_t)); // udata // allocate memory that going to be automotically collected when not necessary anymore
    bsd_init(ctx);
    addm3daclassdef(ctx);
    
    do {
        int r = bsd_read( ctx, &data, buffer + offset, bufferlen - offset);
        if (r<0)
        {
            lua_pushnil(    L);
            lua_pushstring( L, "partial");
            return 2;
        }

        if ( bysant2lua( L, &data, offset, r) )
        {
            bsd_init(ctx);
            lua_pushnil(L);
            lua_insert(L, -2);
            return 2;
        }
        offset += r;
    } while( ctx->stacksize > 0);


    lua_pushinteger( L, offset+1);
    return 3;
    
}

// // Add data to the deserializer object
// static int api_adddata( lua_State *L)
// {
// }


static const struct luaL_Reg bysantdlib[] =
{
    {"deserialize", api_deserialize},
    {NULL, NULL},
};


int luaopen_bysant( lua_State *L)
{

    /* set niltoken in registry as shortcut*/
    //Note: maybe to be moved into bysant.core.c
    lua_getglobal( L, "require");     // m3da.bysant.core, require
    lua_pushstring( L, "niltoken");   // m3da.bysant.core, require, "niltoken"
    int pcall_res = lua_pcall( L, 1, 1, 0);               // m3da.bysant.core, niltoken or errmsg
    if (pcall_res){ //require niltoken failed
        //pop error message
        lua_pop( L, 1); // m3da.bysant.core
        //push nil as m3da.bysant 'default' niltoken
        lua_pushnil(L); // m3da.bysant.core, nil
        //Note: at some point we may want to inform somebody, somehow that we couln't use
        //'real' niltoken as this implies some limitations: M3DA null coming from server is likely to be poorly handled in this case
    }
    //store niltoken as reference in reference system, to be used by push_niltoken later on.
    niltoken_reg = luaL_ref(L, LUA_REGISTRYINDEX); // m3da.bysant.core



    
    luaL_register(L, "bysant", bysantdlib);
    return 1;
}