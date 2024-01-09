package gosleigh

// #cgo LDFLAGS: -lsleigh -lstdc++ -lm
//
// #include <stdlib.h>
// #include <sleigh.h>
// #include <sleigh_float.h>
import (
	"C"
)
import (
	"fmt"
	"log"
	"strings"
	"unsafe"
)

const (
	SLEIGH_CPUI_COPY              = 1
	SLEIGH_CPUI_LOAD              = 2
	SLEIGH_CPUI_STORE             = 3
	SLEIGH_CPUI_BRANCH            = 4
	SLEIGH_CPUI_CBRANCH           = 5
	SLEIGH_CPUI_BRANCHIND         = 6
	SLEIGH_CPUI_CALL              = 7
	SLEIGH_CPUI_CALLIND           = 8
	SLEIGH_CPUI_CALLOTHER         = 9
	SLEIGH_CPUI_RETURN            = 10
	SLEIGH_CPUI_INT_EQUAL         = 11
	SLEIGH_CPUI_INT_NOTEQUAL      = 12
	SLEIGH_CPUI_INT_SLESS         = 13
	SLEIGH_CPUI_INT_SLESSEQUAL    = 14
	SLEIGH_CPUI_INT_LESS          = 15
	SLEIGH_CPUI_INT_LESSEQUAL     = 16
	SLEIGH_CPUI_INT_ZEXT          = 17
	SLEIGH_CPUI_INT_SEXT          = 18
	SLEIGH_CPUI_INT_ADD           = 19
	SLEIGH_CPUI_INT_SUB           = 20
	SLEIGH_CPUI_INT_CARRY         = 21
	SLEIGH_CPUI_INT_SCARRY        = 22
	SLEIGH_CPUI_INT_SBORROW       = 23
	SLEIGH_CPUI_INT_2COMP         = 24
	SLEIGH_CPUI_INT_NEGATE        = 25
	SLEIGH_CPUI_INT_XOR           = 26
	SLEIGH_CPUI_INT_AND           = 27
	SLEIGH_CPUI_INT_OR            = 28
	SLEIGH_CPUI_INT_LEFT          = 29
	SLEIGH_CPUI_INT_RIGHT         = 30
	SLEIGH_CPUI_INT_SRIGHT        = 31
	SLEIGH_CPUI_INT_MULT          = 32
	SLEIGH_CPUI_INT_DIV           = 33
	SLEIGH_CPUI_INT_SDIV          = 34
	SLEIGH_CPUI_INT_REM           = 35
	SLEIGH_CPUI_INT_SREM          = 36
	SLEIGH_CPUI_BOOL_NEGATE       = 37
	SLEIGH_CPUI_BOOL_XOR          = 38
	SLEIGH_CPUI_BOOL_AND          = 39
	SLEIGH_CPUI_BOOL_OR           = 40
	SLEIGH_CPUI_FLOAT_EQUAL       = 41
	SLEIGH_CPUI_FLOAT_NOTEQUAL    = 42
	SLEIGH_CPUI_FLOAT_LESS        = 43
	SLEIGH_CPUI_FLOAT_LESSEQUAL   = 44
	SLEIGH_CPUI_FLOAT_NAN         = 46
	SLEIGH_CPUI_FLOAT_ADD         = 47
	SLEIGH_CPUI_FLOAT_DIV         = 48
	SLEIGH_CPUI_FLOAT_MULT        = 49
	SLEIGH_CPUI_FLOAT_SUB         = 50
	SLEIGH_CPUI_FLOAT_NEG         = 51
	SLEIGH_CPUI_FLOAT_ABS         = 52
	SLEIGH_CPUI_FLOAT_SQRT        = 53
	SLEIGH_CPUI_FLOAT_INT2FLOAT   = 54
	SLEIGH_CPUI_FLOAT_FLOAT2FLOAT = 55
	SLEIGH_CPUI_FLOAT_TRUNC       = 56
	SLEIGH_CPUI_FLOAT_CEIL        = 57
	SLEIGH_CPUI_FLOAT_FLOOR       = 58
	SLEIGH_CPUI_FLOAT_ROUND       = 59
	SLEIGH_CPUI_MULTIEQUAL        = 60
	SLEIGH_CPUI_INDIRECT          = 61
	SLEIGH_CPUI_PIECE             = 62
	SLEIGH_CPUI_SUBPIECE          = 63
	SLEIGH_CPUI_CAST              = 64
	SLEIGH_CPUI_PTRADD            = 65
	SLEIGH_CPUI_PTRSUB            = 66
	SLEIGH_CPUI_SEGMENTOP         = 67
	SLEIGH_CPUI_CPOOLREF          = 68
	SLEIGH_CPUI_NEW               = 69
	SLEIGH_CPUI_INSERT            = 70
	SLEIGH_CPUI_EXTRACT           = 71
	SLEIGH_CPUI_POPCOUNT          = 72
	SLEIGH_CPUI_LZCOUNT           = 73
	SLEIGH_CPUI_MAX               = 74
)

const (
	SLEIGH_ARCH_X86_64 = 1
	SLEIGH_ARCH_X86    = 2
	SLEIGH_ARCH_ARM    = 3
)

const (
	SLEIGH_PROC_X86_64      = 1
	SLEIGH_PROC_X86_16      = 2
	SLEIGH_PROC_X86_16_REAL = 3
	SLEIGH_PROC_X86         = 4
	SLEIGH_PROC_ARM7LE      = 5
	SLEIGH_PROC_ARM7BE      = 6
)

type SleighCtx struct {
	arch, proc int
	ptr        C.sleigh_ctx_t
}

type SleighOpcode C.sleigh_opcode_t
type SleighSpace struct {
	ptr  C.sleigh_address_space_t
	name string
}

type SleighAddr struct {
	Space  *SleighSpace
	Offset uint64
}

type SleighSecNum struct {
	addr  SleighAddr
	uniq  uint32
	order uint32
}

type SleighVarnode struct {
	space  *SleighSpace
	Offset uint64
	Size   uint32
}

type SleighRegister struct {
	Varnode SleighVarnode
	Name    string
}

type SleighOp struct {
	seq    SleighSecNum
	Opcode SleighOpcode
	Inputs []*SleighVarnode
	Output *SleighVarnode
}

type SleighInstruction struct {
	Addr     SleighAddr
	Len      uint32
	Mnemonic string
	Body     string
	Ops      []SleighOp
}

type FloatFormat struct {
	ptr  C.sleigh_float_format_t
	Size int
}

func OpcodeName(opcode SleighOpcode) string {
	return C.GoString(C.sleigh_opcode_name(C.sleigh_opcode_t(opcode)))
}

func makeSleighSpace(ptr C.sleigh_address_space_t) *SleighSpace {
	return &SleighSpace{
		ptr:  ptr,
		name: "",
	}
}

func CreateContext(arch int, proc int) (*SleighCtx, error) {
	res := &SleighCtx{
		arch: arch,
		proc: proc,
		ptr:  C.sleigh_create_context(C.sleigh_arch_t(arch), C.sleigh_processor_t(proc)),
	}
	if res.ptr == nil {
		err := C.GoString(C.sleigh_get_last_error())
		return nil, fmt.Errorf("unable to create context [%s]", err)
	}
	return res, nil
}

func processTranslationResult(r *C.sleigh_translation_result_t) []*SleighInstruction {
	res := make([]*SleighInstruction, 0)
	for i := 0; i < int(r.instructions_count); i++ {
		instrPtr := *(*C.sleigh_translation_t)(
			unsafe.Add(unsafe.Pointer(r.instructions), unsafe.Sizeof(*r.instructions)*uintptr(i)))
		instr := &SleighInstruction{
			Addr: SleighAddr{
				Space:  makeSleighSpace(instrPtr.address.space),
				Offset: uint64(instrPtr.address.offset),
			},
			Len:      uint32(instrPtr.length),
			Mnemonic: C.GoString(instrPtr.asm_mnem),
			Body:     C.GoString(instrPtr.asm_body),
			Ops:      make([]SleighOp, instrPtr.ops_count),
		}

		numOps := len(instr.Ops)
		for i := 0; i < numOps; i++ {
			cop := *(*C.sleigh_pcodeop_t)(
				unsafe.Add(unsafe.Pointer(instrPtr.ops), unsafe.Sizeof(*instrPtr.ops)*uintptr(i)))

			inputs := make([]*SleighVarnode, 0)
			for j := 0; j < int(cop.inputs_count); j++ {
				inp := *(*C.sleigh_varnode_t)(
					unsafe.Add(unsafe.Pointer(cop.inputs), unsafe.Sizeof(*cop.inputs)*uintptr(j)))
				inputs = append(inputs, &SleighVarnode{
					space:  makeSleighSpace(inp.space),
					Offset: uint64(inp.offset),
					Size:   uint32(inp.size),
				})
			}
			var output *SleighVarnode = nil
			if cop.output != nil {
				out := (*C.sleigh_varnode_t)(unsafe.Pointer(cop.output))
				output = &SleighVarnode{
					space:  makeSleighSpace(out.space),
					Offset: uint64(out.offset),
					Size:   uint32(out.size),
				}
			}

			instr.Ops[i] = SleighOp{
				seq: SleighSecNum{
					addr: SleighAddr{
						Space:  makeSleighSpace(cop.seq.pc.space),
						Offset: uint64(cop.seq.pc.offset),
					},
					uniq:  uint32(cop.seq.uniq),
					order: uint32(cop.seq.order),
				},
				Opcode: SleighOpcode(cop.opcode),
				Inputs: inputs,
				Output: output,
			}
		}
		res = append(res, instr)
	}
	return res
}

func (c *SleighCtx) TranslateInstruction(addr uint64, bytes []byte) (*SleighInstruction, error) {
	rawBuf := unsafe.Pointer(&bytes[0])
	rawBufLen := C.uint(len(bytes))

	r := C.sleigh_translate(c.ptr, (*C.uchar)(rawBuf), rawBufLen, C.uint64_t(addr), 1, 0)
	defer C.sleigh_destroy_translation_result(r)
	if r.error.text != nil {
		return nil, fmt.Errorf("unable to decompile [%s]", C.GoString(r.error.text))
	}

	instrs := processTranslationResult(r)
	if len(instrs) != 1 {
		log.Fatalf("unexpected number of instructions %d", len(instrs))
	}
	return instrs[0], nil
}

func (c *SleighCtx) TranslateBasicBlock(addr uint64, bytes []byte) ([]*SleighInstruction, error) {
	rawBuf := unsafe.Pointer(&bytes[0])
	rawBufLen := C.uint(len(bytes))

	r := C.sleigh_translate(c.ptr, (*C.uchar)(rawBuf), rawBufLen, C.uint64_t(addr), 0, 1)
	defer C.sleigh_destroy_translation_result(r)
	if r.error.text != nil {
		return nil, fmt.Errorf("unable to decompile [%s]", C.GoString(r.error.text))
	}

	return processTranslationResult(r), nil
}

func (c *SleighCtx) GetSpaceByName(name string) (*SleighSpace, error) {
	raw := C.sleigh_get_space_by_name(c.ptr, C.CString(name))
	if raw == nil {
		return nil, fmt.Errorf("no such space")
	}
	return makeSleighSpace(raw), nil
}

func (c *SleighCtx) GetRegName(v *SleighVarnode) string {
	varnodeStruct := v.cStruct()
	cName := C.sleigh_get_register_name(c.ptr, &varnodeStruct)
	return C.GoString(cName)
}

func (c *SleighCtx) GetRegister(name string) (*SleighVarnode, error) {
	var raw_varnode C.sleigh_varnode_t
	if !C.sleigh_get_register(c.ptr, C.CString(name), (*C.sleigh_varnode_t)(unsafe.Pointer(&raw_varnode))) {
		return nil, fmt.Errorf("no such register")
	}
	return &SleighVarnode{
		space:  makeSleighSpace(raw_varnode.space),
		Offset: uint64(raw_varnode.offset),
		Size:   uint32(raw_varnode.size),
	}, nil
}

func (c *SleighCtx) GetAllRegisters() []SleighRegister {
	var regs *C.sleigh_register_t
	var size C.size_t
	C.sleigh_get_all_registers(c.ptr, (**C.sleigh_register_t)(unsafe.Pointer(&regs)), (*C.size_t)(unsafe.Pointer(&size)))
	defer C.free(unsafe.Pointer(regs))

	res := make([]SleighRegister, 0)
	for i := 0; i < int(size); i++ {
		reg := *(*C.sleigh_register_t)(unsafe.Add(unsafe.Pointer(regs), unsafe.Sizeof(*regs)*uintptr(i)))
		goreg := SleighRegister{
			Name: "",
			Varnode: SleighVarnode{
				space:  makeSleighSpace(reg.varnode.space),
				Offset: uint64(reg.varnode.offset),
				Size:   uint32(reg.varnode.size),
			},
		}

		var name strings.Builder
		for j := 0; j < 32; j++ {
			c := reg.name[j]
			if c == 0 {
				break
			}
			name.WriteByte(byte(c))
		}
		goreg.Name = name.String()
		res = append(res, goreg)
	}
	return res
}

func (c *SleighCtx) VarnodeToString(v *SleighVarnode) string {
	spaceName := v.space.Name()
	if spaceName == "register" {
		return c.GetRegName(v)
	}
	if spaceName == "unique" {
		return fmt.Sprintf("TMP_%d:%d", v.Offset, v.Size)
	}
	if spaceName == "const" {
		return fmt.Sprintf("0x%x", v.Offset)
	}
	return fmt.Sprintf("%s[0x%x:%d]", spaceName, v.Offset, v.Size)
}

func mkFloatFormat(ptr C.sleigh_float_format_t, size int) *FloatFormat {
	return &FloatFormat{ptr: ptr, Size: size}
}

func (c *SleighCtx) GetHostFloat(size int) (*FloatFormat, error) {
	ff := C.sleigh_get_host_float(c.ptr, C.int(size))
	if ff == nil {
		return mkFloatFormat(nil, 0), fmt.Errorf("host float with size %d not found", size)
	}
	return mkFloatFormat(ff, size), nil
}

func (c *SleighCtx) Delete() {
	C.sleigh_destroy_context(C.sleigh_ctx_t(c.ptr))
}

func (insn *SleighInstruction) Asm() string {
	return fmt.Sprintf("%08xh: %s %s", insn.Addr.Offset, insn.Mnemonic, insn.Body)
}

func (c *SleighCtx) PCodeStrings(insn *SleighInstruction) []string {
	res := make([]string, 0)
	for i := range insn.Ops {
		op := &insn.Ops[i]

		var opstr strings.Builder
		opstr.WriteString(C.GoString(C.sleigh_opcode_name(C.sleigh_opcode_t(op.Opcode))))
		opstr.WriteString(" ")

		switch op.Opcode {
		case SLEIGH_CPUI_LOAD:
			dstSpace, _ := op.Inputs[0].GetConstSpace()
			opstr.WriteString(c.VarnodeToString(op.Output))
			opstr.WriteString(" <- ")
			opstr.WriteString(dstSpace.Name())
			opstr.WriteString("[")
			opstr.WriteString(c.VarnodeToString(op.Inputs[1]))
			opstr.WriteString("]")
		case SLEIGH_CPUI_STORE:
			dstSpace, _ := op.Inputs[0].GetConstSpace()
			opstr.WriteString(dstSpace.Name())
			opstr.WriteString("[")
			opstr.WriteString(c.VarnodeToString(op.Inputs[1]))
			opstr.WriteString("]")
			opstr.WriteString(" <- ")
			opstr.WriteString(c.VarnodeToString(op.Inputs[2]))
		default:
			if op.Output != nil {
				opstr.WriteString(c.VarnodeToString(op.Output))
				opstr.WriteString(" <- ")
			}
			for j := range op.Inputs {
				inp := op.Inputs[j]
				if j > 0 {
					opstr.WriteString(", ")
				}
				opstr.WriteString(c.VarnodeToString(inp))
			}
		}
		res = append(res, opstr.String())
	}
	return res
}

func (space *SleighSpace) Name() string {
	if space.name == "" {
		space.name = C.GoString(C.sleigh_get_space_name(C.sleigh_address_space_t(space.ptr)))
	}
	return space.name
}

func (varnode *SleighVarnode) cStruct() C.sleigh_varnode_t {
	return C.sleigh_varnode_t{
		space:  C.sleigh_address_space_t(varnode.space.ptr),
		offset: C.uint64_t(varnode.Offset),
		size:   C.uint(varnode.Size),
	}
}

func (varnode *SleighVarnode) IsRegister() bool {
	cstruct := varnode.cStruct()
	return bool(C.sleigh_varnode_is_register(&cstruct))
}

func (varnode *SleighVarnode) IsUnique() bool {
	cstruct := varnode.cStruct()
	return bool(C.sleigh_varnode_is_unique(&cstruct))
}

func (varnode *SleighVarnode) IsConst() bool {
	cstruct := varnode.cStruct()
	return bool(C.sleigh_varnode_is_const(&cstruct))
}

func (varnode *SleighVarnode) GetConstSpace() (*SleighSpace, error) {
	cstruct := varnode.cStruct()
	r := C.sleigh_varnode_get_const_space(&cstruct)
	if r == nil {
		return makeSleighSpace(nil), fmt.Errorf("not a const")
	}
	return makeSleighSpace(r), nil
}

// *** FLOATS ***

func (ff *FloatFormat) GetEncoding(d float64) uint64 {
	r := C.float_format_get_encoding(ff.ptr, C.double(d))
	return uint64(r)
}

func (ff *FloatFormat) GetHostFloat(e uint64) float64 {
	r := C.float_format_get_host_float(ff.ptr, C.uint64_t(e))
	return float64(r)
}

func (ff *FloatFormat) ConvertEncoding(from *FloatFormat, e uint64) float64 {
	r := C.float_format_convert_encoding(from.ptr, ff.ptr, C.uint64_t(e))
	return float64(r)
}

func (ff *FloatFormat) OpEqual(a, b uint64) uint64 {
	return uint64(C.float_format_op_Equal(ff.ptr, C.uint64_t(a), C.uint64_t(b)))
}

func (ff *FloatFormat) OpNotEqual(a, b uint64) uint64 {
	return uint64(C.float_format_op_NotEqual(ff.ptr, C.uint64_t(a), C.uint64_t(b)))
}
func (ff *FloatFormat) OpLess(a, b uint64) uint64 {
	return uint64(C.float_format_op_Less(ff.ptr, C.uint64_t(a), C.uint64_t(b)))
}
func (ff *FloatFormat) OpLessEqual(a, b uint64) uint64 {
	return uint64(C.float_format_op_LessEqual(ff.ptr, C.uint64_t(a), C.uint64_t(b)))
}
func (ff *FloatFormat) OpAdd(a, b uint64) uint64 {
	return uint64(C.float_format_op_Add(ff.ptr, C.uint64_t(a), C.uint64_t(b)))
}
func (ff *FloatFormat) OpDiv(a, b uint64) uint64 {
	return uint64(C.float_format_op_Div(ff.ptr, C.uint64_t(a), C.uint64_t(b)))
}
func (ff *FloatFormat) OpMult(a, b uint64) uint64 {
	return uint64(C.float_format_op_Mult(ff.ptr, C.uint64_t(a), C.uint64_t(b)))
}
func (ff *FloatFormat) OpSub(a, b uint64) uint64 {
	return uint64(C.float_format_op_Sub(ff.ptr, C.uint64_t(a), C.uint64_t(b)))
}

func (ff *FloatFormat) OpNan(a uint64) uint64 {
	return uint64(C.float_format_op_Nan(ff.ptr, C.uint64_t(a)))
}

func (ff *FloatFormat) OpNeg(a uint64) uint64 {
	return uint64(C.float_format_op_Neg(ff.ptr, C.uint64_t(a)))
}

func (ff *FloatFormat) OpAbs(a uint64) uint64 {
	return uint64(C.float_format_op_Abs(ff.ptr, C.uint64_t(a)))
}

func (ff *FloatFormat) OpSqrt(a uint64) uint64 {
	return uint64(C.float_format_op_Sqrt(ff.ptr, C.uint64_t(a)))
}

func (ff *FloatFormat) OpCeil(a uint64) uint64 {
	return uint64(C.float_format_op_Ceil(ff.ptr, C.uint64_t(a)))
}

func (ff *FloatFormat) OpFloor(a uint64) uint64 {
	return uint64(C.float_format_op_Floor(ff.ptr, C.uint64_t(a)))
}

func (ff *FloatFormat) OpRound(a uint64) uint64 {
	return uint64(C.float_format_op_Round(ff.ptr, C.uint64_t(a)))
}

func (ff *FloatFormat) OpTrunc(a uint64, sizeout int32) uint64 {
	return uint64(C.float_format_op_Trunc(ff.ptr, C.uint64_t(a), C.uint(sizeout)))
}

func (ff *FloatFormat) OpInt2Float(a uint64, sizein int32) uint64 {
	return uint64(C.float_format_op_Int2Float(ff.ptr, C.uint64_t(a), C.uint(sizein)))
}
