#include <cstring>
#include <iostream>
#include <memory>

#include <cstdio>
extern "C" {
#include <libyasm.h>
#include <libyasm/bitvect.h>
}


long _fake_line = 1;
auto next_fake_line(long base = 0) -> long {
    auto r = base + _fake_line;
    _fake_line += 1;
    return r;
}

template <typename Type, typename Base, typename Module, yasm_module_type type>
struct YasmModuleTraits {
    struct Deleter {
        void operator() (Type* p) {
            reinterpret_cast<Base*>(p)->module->destroy(p);
        }
    };
    using Unique = std::unique_ptr<Type, Deleter>;

    static auto load_module(const char* kw) -> Module* {
        void* loaded = yasm_load_module(type, kw);
        if (!loaded) {
            throw std::runtime_error(std::string("Could not load module ") + kw);
        }
        return reinterpret_cast<Module*>(loaded);
    }

    static void list_modules() {
        yasm_list_modules(type, [](const char* name, const char* kw) {
            std::cout << '"' << name << "\" (" << kw << ")" << std::endl;
        });
    }

    template <typename... Args>
    static auto create(Module* m, Args&&... args) -> Unique {
        auto* r = m->create(std::forward<Args>(args)...);
        if (!r) {
            throw std::runtime_error("Unable to create object");
        }
        return Unique(r);
    }
};

using YasmArch = YasmModuleTraits<yasm_arch, yasm_arch_base, yasm_arch_module, YASM_MODULE_ARCH>;
using YasmObjfmt = YasmModuleTraits<yasm_objfmt, yasm_objfmt_base, yasm_objfmt_module, YASM_MODULE_OBJFMT>;
using YasmDbgfmt = YasmModuleTraits<yasm_dbgfmt, yasm_dbgfmt_base, yasm_dbgfmt_module, YASM_MODULE_DBGFMT>;
using YasmPreproc = YasmModuleTraits<yasm_preproc, yasm_preproc_base, yasm_preproc_module, YASM_MODULE_PREPROC>;

template <typename Type, Type* (*create) (), void (*destroy) (Type*)>
class YasmObject {
    struct Deleter {
        void operator() (Type* p) {
            destroy(p);
        }
    };

    std::unique_ptr<Type, Deleter> up;

public:
    YasmObject() : up(create()) {}
    YasmObject(YasmObject&&) = default;

    operator Type* () {
        return up.get();
    }

    operator Type* () const {
        return up.get();
    }
};

using YasmErrwarns = YasmObject<yasm_errwarns, &yasm_errwarns_create, &yasm_errwarns_destroy>;
using YasmLinemap = YasmObject<yasm_linemap, &yasm_linemap_create, &yasm_linemap_destroy>;
using YasmSymtab = YasmObject<yasm_symtab, &yasm_symtab_create, &yasm_symtab_destroy>;

struct YasmObjectFileDeleter {
    void operator() (yasm_object* p) {
        // to avoid double-freeing the arch that is managed by its own unique ptr
        p->arch = nullptr;
        yasm_object_destroy(p);
    }
};

using YasmObjectFile = std::unique_ptr<yasm_object, YasmObjectFileDeleter>;


void check_errors(const YasmErrwarns& errwarns, const YasmLinemap& linemap)
{
    int warning_error = 1; // treat warnings as errors
    auto print_error = []( const char* filename, unsigned long line, const char* msg
                         , const char* xref_fn, unsigned long xref_line, const char* xref_msg
                         ) {
        std::cerr << filename << ":" << line << " error: " << msg << std::endl;
        if (!xref_fn or !xref_msg)  return;
        std::cerr << xref_fn << ":" << xref_line << " error: " << xref_msg << std::endl;
    };
    auto print_warning = []( const char* filename, unsigned long line, const char* msg) {
        std::cerr << filename << ":" << line << " error: " << msg << std::endl;
    };
    if (yasm_errwarns_num_errors(errwarns, warning_error) > 0)
    {
        yasm_errwarns_output_all
            ( errwarns, linemap, warning_error
            , print_error, print_warning
            );
        throw std::runtime_error("Exiting because of the above errors");
    }
}

auto make_effaddr(const YasmArch::Unique& arch, const char* basereg_name, const char* indreg_name, unsigned long shift, unsigned long offset)
    -> yasm_effaddr*
{
    uintptr_t basereg_reg;
    if ( auto r = yasm_arch_parse_check_regtmod
            ( arch.get()
            , basereg_name, std::strlen(basereg_name)
            , &basereg_reg
            )
       ; r != YASM_ARCH_REG
       ) {
        throw std::logic_error("Not a register " + std::to_string(r));
    }
    uintptr_t indreg_reg;
    if ( auto r = yasm_arch_parse_check_regtmod
            ( arch.get()
            , indreg_name, std::strlen(indreg_name)
            , &indreg_reg
            )
       ; r != YASM_ARCH_REG
       ) {
        throw std::logic_error("Not a register " + std::to_string(r));
    }

    auto check_null = [](auto* p) {
        if (p == nullptr) {
            throw std::runtime_error("Nullptr in expr creation");
        }
    };

    yasm_expr__item* basereg_item = yasm_expr_reg(basereg_reg);
    check_null(basereg_item);
    yasm_expr__item* indreg_item = yasm_expr_reg(indreg_reg);
    check_null(indreg_item);
    yasm_expr__item* offset_item = yasm_expr_int(yasm_intnum_create_uint(offset));
    check_null(offset_item);
    yasm_expr__item* shift_item = yasm_expr_int(yasm_intnum_create_uint(shift));
    check_null(shift_item);

    yasm_expr__item* shifted_index = yasm_expr_expr(yasm_expr_create
        (YASM_EXPR_SHL, indreg_item, shift_item, 101));
    check_null(shifted_index);
    yasm_expr__item* index_plus_base = yasm_expr_expr(yasm_expr_create
        (YASM_EXPR_ADD, basereg_item, shifted_index, 102));
    check_null(index_plus_base);
    yasm_expr* final_sum = yasm_expr_create
        (YASM_EXPR_ADD, offset_item, index_plus_base, 103);
    check_null(final_sum);

    auto* ea = yasm_arch_ea_create(arch.get(), final_sum);
    if (ea == nullptr) {
        throw std::runtime_error("Could not create effective address");
    }

    return ea;
}

template <size_t len>
auto instruction(const YasmArch::Unique& arch, const char opcode[len])
    -> yasm_bytecode*
{
    yasm_bytecode* bc = nullptr;
    uintptr_t prefix = 0;
    auto type = yasm_arch_parse_check_insnprefix
        ( arch.get()
        , opcode, len
        , next_fake_line(200)
        , &bc, &prefix
        );
    if (type != YASM_ARCH_INSN) {
        throw std::logic_error("Not an instruction");
    }
    if (!bc) {
        throw std::logic_error("No bytecode generated");
    }
    return bc;
}

auto gen_mov_reg(const YasmArch::Unique& arch, const char* regname, unsigned long value) -> yasm_bytecode*
{
    uintptr_t reg_value;
    auto r = yasm_arch_parse_check_regtmod(arch.get(), regname, std::strlen(regname), &reg_value);
    if (r != YASM_ARCH_REG) {
        throw std::logic_error("Not a register " + std::to_string(r));
    }

    auto* bc = instruction<3>(arch, "mov");
    yasm_insn* insn = yasm_bc_get_insn(bc);

    yasm_expr__item* item_reg = yasm_expr_reg(reg_value);
    yasm_expr* expr_reg = yasm_expr_create(YASM_EXPR_IDENT, item_reg, nullptr, 1);
    yasm_insn_operand* op_reg = yasm_operand_create_imm(expr_reg);
    // append to instruction
    if (auto* t = yasm_insn_ops_append(insn, op_reg); not t) {
        std::cout << "could not append operand reg" << std::endl;
    }

    // create operand from ulong
    yasm_intnum* value_long = yasm_intnum_create_uint(value);
    yasm_expr__item* item_long = yasm_expr_int(value_long);
    yasm_expr* expr_long = yasm_expr_create(YASM_EXPR_IDENT, item_long, nullptr, 1);
    yasm_insn_operand* op_long = yasm_operand_create_imm(expr_long);
    // append to instruction
    if (auto* t = yasm_insn_ops_append(insn, op_long); not t) {
        std::cout << "could not append operand long" << std::endl;
    }

    return bc;
}

int main()
{
    /* initialize dependencies */
    if (auto r = BitVector_Boot(); r != ErrCode_Ok) {
        std::cerr << "unable to initializer bitvector" << std::endl;
        return r;
    }
    yasm_intnum_initialize();
    yasm_floatnum_initialize();
    yasm_errwarn_initialize();

    const char* output_name = "assembled.o";

    std::cout << "\navailable arch modules:" << std::endl;
    YasmArch::list_modules();
    auto* x86_module = YasmArch::load_module("x86");

    std::cout << "module machines:" << std::endl;
    auto* machine = x86_module->machines;
    while (machine->name != nullptr) {
        std::cout << machine->name << " (" << machine->keyword << ")" << std::endl;
        machine += 1;
    }

    yasm_arch_create_error err;
    auto arch = YasmArch::create(x86_module, "amd64", "nasm", &err);
    if (err != YASM_ARCH_CREATE_OK) {
        std::cerr << "Arch create error: " << err << std::endl;
        return 1;
    }

    if (auto t = yasm_arch_set_var(arch.get(), "mode_bits", 64); not t) {
        std::cout << "could not set 64 bit mode" << std::endl;
    }

    /* create empty errwarns (not sure if really empty) */
    YasmErrwarns errwarns;
    /* create identity linemap (not sure if really identity) */
    YasmLinemap linemap;
    yasm_linemap_set(linemap, "-", 0, 1, 1);

    /* list and create objfmt */
    std::cout << "\navailable objfmts:" << std::endl;
    YasmObjfmt::list_modules();
    auto objfmt = YasmObjfmt::load_module("elf");

    /* list and create dbgfmt */
    std::cout << "\navailable dbgfmts:" << std::endl;
    YasmDbgfmt::list_modules();
    auto dbgfmt = YasmDbgfmt::load_module("null");

    /* create elf-object-file representative */
    auto object = YasmObjectFile(yasm_object_create
        ( "-", output_name, arch.get()
        , objfmt, dbgfmt
        ));

    auto* symtab = object->symtab;

    /* get section .text */
    std::cout << std::endl;
    int is_new_section = 0;
    // text should already exist
    yasm_section* section_text = yasm_object_get_general(object.get(), ".text", 16, true /* is code */, false /* not bss */, &is_new_section, 1);
    if (is_new_section) {
        std::cout << ".text was created, this shouldn't happen" << std::endl;
    }
    /* create section .data with correct (default) params */
    yasm_valparamhead vps;
    yasm_vps_initialize(&vps);
    auto* data_identifier = yasm__xstrdup(".data");
    yasm_valparam* vp = yasm_vp_create_id(nullptr, data_identifier, '\0');
    yasm_vps_append(&vps, vp);
    yasm_section* section_data = yasm_objfmt_section_switch(object.get(), &vps, nullptr, next_fake_line());
    yasm_vps_delete(&vps);

    yasm_bytecode* bc;

    /*****************/
    /* section .data */

    /* start and symbol for msg */

    bc = x86_module->create_empty_insn(arch.get(), 1);
    if (auto t = yasm_section_bcs_append(section_data, bc); not t) {
        std::cerr << "failed to append bytecode to section data" << std::endl;
    }
    yasm_symtab_define_label
        ( symtab, "msg"
        , bc, 1 /* is insered into table */, next_fake_line()
        );

    /* data for msg */

    constexpr const char content_str_lit[] = "Hello, World\n";
    auto* content_str = yasm__xstrdup(content_str_lit);
    yasm_dataval* string_val = yasm_dv_create_string(content_str, std::size(content_str_lit) - 1);
    yasm_datavalhead datavals;
    yasm_dvs_initialize(&datavals);
    yasm_dvs_append(&datavals, string_val);
    bc = yasm_bc_create_data
        ( &datavals, std::size(content_str_lit) - 1
        , 0 /* do not append zero */
        , arch.get(), 1
        );
    // finally append
    if (auto t = yasm_section_bcs_append(section_data, bc); not t) {
        std::cerr << "failed to append bytecode to section data" << std::endl;
    }

    /*****************/
    /* section .text */

    /* symbol for start */
    bc = x86_module->create_empty_insn(arch.get(), 1);
    if (auto t = yasm_section_bcs_append(section_text, bc); not t) {
        std::cerr << "failed to append bytecode to section text" << std::endl;
    }
    yasm_symrec* start_sym = yasm_symtab_define_label
        ( symtab, "_start"
        , bc, 1, next_fake_line()
        );
    yasm_symrec_declare(start_sym, YASM_SYM_GLOBAL, next_fake_line());

    /* mov rax, 1 (sys_write) */
    bc = gen_mov_reg(arch, "rax", 1);
    if (auto t = yasm_section_bcs_append(section_text, bc); not t) {
        std::cerr << "failed to append bytecode to section text" << std::endl;
    }
    /* mov rdi, 1 (stdout) */
    bc = gen_mov_reg(arch, "rdi", 1);
    if (auto t = yasm_section_bcs_append(section_text, bc); not t) {
        std::cerr << "failed to append bytecode to section text" << std::endl;
    }
    /* slight interjection: mov word ptr [0x402000 + rax + rdi<<0], 'ww' */
    // create instruction
    bc = instruction<3>(arch, "mov");
    yasm_insn* insn = yasm_bc_get_insn(bc);
    // create effective address
    yasm_effaddr* ea = make_effaddr(arch, "rax", "rdi", 0, 0x402000);
    ea->data_len = 2;
    // ea to operand
    yasm_insn_operand* op_ea = yasm_operand_create_mem(ea);
    // append to instruction
    if (auto* t = yasm_insn_ops_append(insn, op_ea); not t) {
        std::cout << "could not append operand address" << std::endl;
    }
    // create int operand
    yasm_expr__item* item_72 = yasm_expr_int(yasm_intnum_create_uint(0x7777));
    yasm_expr* expr_72 = yasm_expr_create(YASM_EXPR_IDENT, item_72, nullptr, 104);
    yasm_insn_operand* op_72 = yasm_operand_create_imm(expr_72);
    // append to instruction
    if (auto* t = yasm_insn_ops_append(insn, op_72); not t) {
        std::cout << "could not append operand address" << std::endl;
    }
    // append instruction itself
    if (auto t = yasm_section_bcs_append(section_text, bc); not t) {
        std::cerr << "failed to append bytecode to section text" << std::endl;
    }

    /* mov rsi, msg  */
    // create instruction
    bc = instruction<3>(arch, "mov");
    insn = yasm_bc_get_insn(bc);
    // create register
    uintptr_t reg_value = 0;
    auto r = yasm_arch_parse_check_regtmod(arch.get(), "rsi", 3, &reg_value);
    if (r != YASM_ARCH_REG) {
        throw std::logic_error("Not a register " + std::to_string(r));
    }
    // register to operand
    yasm_expr__item* item_reg = yasm_expr_reg(reg_value);
    yasm_expr* expr_reg = yasm_expr_create(YASM_EXPR_IDENT, item_reg, nullptr, 1);
    yasm_insn_operand* op_reg = yasm_operand_create_imm(expr_reg);
    // append to instruction
    if (auto* t = yasm_insn_ops_append(insn, op_reg); not t) {
        std::cout << "could not append operand reg" << std::endl;
    }
    // create operand from label
    yasm_symrec* msg_sym_used = yasm_symtab_use(symtab, "msg", next_fake_line());
    yasm_expr__item* item_sym = yasm_expr_sym(msg_sym_used);
    yasm_expr* expr_sym = yasm_expr_create(YASM_EXPR_IDENT, item_sym, nullptr, 1);
    yasm_insn_operand* op_sym = yasm_operand_create_imm(expr_sym);
    // append to instruction
    if (auto* t = yasm_insn_ops_append(insn, op_sym); not t) {
        std::cout << "could not append operand sym" << std::endl;
    }
    // append instruction itself
    if (auto t = yasm_section_bcs_append(section_text, bc); not t) {
        std::cerr << "failed to append bytecode to section text" << std::endl;
    }
    /* mov rdx, strlen(msg) */
    bc = gen_mov_reg(arch, "rdx", std::size(content_str_lit) - 1);
    if (auto t = yasm_section_bcs_append(section_text, bc); not t) {
        std::cerr << "failed to append bytecode to section text" << std::endl;
    }
    /* syscall */
    bc = instruction<7>(arch, "syscall");
    if (auto t = yasm_section_bcs_append(section_text, bc); not t) {
        std::cerr << "failed to append bytecode to section text" << std::endl;
    }

    /* mov rax, 60 */
    bc = gen_mov_reg(arch, "rax", 60);
    if (auto t = yasm_section_bcs_append(section_text, bc); not t) {
        std::cerr << "failed to append bytecode to section text" << std::endl;
    }
    /* mov rdi, 228 */
    bc = gen_mov_reg(arch, "rdi", 228);
    if (auto t = yasm_section_bcs_append(section_text, bc); not t) {
        std::cerr << "failed to append bytecode to section text" << std::endl;
    }
    /* syscall */
    bc = instruction<7>(arch, "syscall");
    if (auto t = yasm_section_bcs_append(section_text, bc); not t) {
        std::cerr << "failed to append bytecode to section text" << std::endl;
    }

    /* Finalize after adding bytecode */
    yasm_symtab_parser_finalize(symtab, 0, errwarns);
    check_errors(errwarns, linemap);
    yasm_object_finalize(object.get(), errwarns);
    check_errors(errwarns, linemap);

    /* Optimize */
    yasm_object_optimize(object.get(), errwarns);
    check_errors(errwarns, linemap);

    /* Generate any debugging information */
    yasm_dbgfmt_generate(object.get(), linemap, errwarns);
    check_errors(errwarns, linemap);

    /* Write to file */
    FILE* output = fopen(output_name, "wb");
    yasm_objfmt_output(object.get(), output, 0, errwarns);
    fclose(output);
    check_errors(errwarns, linemap);

    yasm_intnum_cleanup();
    yasm_floatnum_cleanup();
    yasm_errwarn_cleanup();
    BitVector_Shutdown();

    return 0;
}
