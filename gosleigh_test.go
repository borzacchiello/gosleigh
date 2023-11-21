package gosleigh

import (
	"testing"
)

func TestContextCreation(t *testing.T) {
	ctx, err := CreateContext(SLEIGH_ARCH_X86_64, SLEIGH_PROC_X86_64)
	if err != nil {
		t.Error(err)
		return
	}
	defer ctx.Delete()
}

func TestTranslate(t *testing.T) {
	ctx, err := CreateContext(SLEIGH_ARCH_X86_64, SLEIGH_PROC_X86_64)
	if err != nil {
		t.Error(err)
		return
	}
	defer ctx.Delete()

	instr, err := ctx.TranslateInstruction(0x1000, []byte{0xb8, 0xef, 0xbe, 0xad, 0xde})
	if err != nil {
		t.Error(err)
		return
	}

	if instr.Asm() != "00001000h: MOV EAX,0xdeadbeef" {
		t.Errorf("invalid asm [%s]", instr.Asm())
		return
	}

	pcodeStrings := ctx.PCodeStrings(instr)
	if len(pcodeStrings) != 1 || pcodeStrings[0] != "COPY RAX <- 0xdeadbeef" {
		t.Error("invalid pcode")
		return
	}
}

func TestTranslateBB(t *testing.T) {
	ctx, err := CreateContext(SLEIGH_ARCH_X86_64, SLEIGH_PROC_X86_64)
	if err != nil {
		t.Error(err)
		return
	}
	defer ctx.Delete()

	instrs, err := ctx.TranslateBasicBlock(0x1000,
		[]byte{0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xBB, 0xFE, 0xCA, 0xAD, 0xAB, 0x31,
			0xD8, 0x39, 0xD0, 0x74, 0x03, 0x90, 0x90, 0x90})
	if err != nil {
		t.Error(err)
		return
	}

	if len(instrs) != 5 {
		t.Error("unexpected number of instructions")
		return
	}

	if instrs[0].Asm() != "00001000h: MOV EAX,0xdeadbeef" {
		t.Errorf("invalid asm [%s]", instrs[0].Asm())
		return
	}
	if instrs[1].Asm() != "00001005h: MOV EBX,0xabadcafe" {
		t.Errorf("invalid asm [%s]", instrs[1].Asm())
		return
	}
	if instrs[2].Asm() != "0000100ah: XOR EAX,EBX" {
		t.Errorf("invalid asm [%s]", instrs[2].Asm())
		return
	}
	if instrs[3].Asm() != "0000100ch: CMP EAX,EDX" {
		t.Errorf("invalid asm [%s]", instrs[3].Asm())
		return
	}
	if instrs[4].Asm() != "0000100eh: JZ 0x1013" {
		t.Errorf("invalid asm [%s]", instrs[4].Asm())
		return
	}
}

func TestGetRegisters(t *testing.T) {
	ctx, err := CreateContext(SLEIGH_ARCH_X86_64, SLEIGH_PROC_X86_64)
	if err != nil {
		t.Error(err)
		return
	}
	defer ctx.Delete()

	regs := ctx.GetAllRegisters()
	if len(regs) != 861 {
		t.Errorf("unexpected number of registers [%d]", len(regs))
		return
	}
}

func TestHostFloats(t *testing.T) {
	ctx, err := CreateContext(SLEIGH_ARCH_X86_64, SLEIGH_PROC_X86_64)
	if err != nil {
		t.Error(err)
		return
	}
	defer ctx.Delete()

	floatEnc, err := ctx.GetHostFloat(4)
	if err != nil {
		t.Error(err)
		return
	}
	doubleEnc, err := ctx.GetHostFloat(8)
	if err != nil {
		t.Error(err)
		return
	}

	if floatEnc.GetEncoding(4.0) != 0x40800000 {
		t.Errorf("unexpected double encoding of 4.0 [0x%x]", floatEnc.GetEncoding(4.0))
		return
	}

	if doubleEnc.GetEncoding(4.0) != 0x4010000000000000 {
		t.Errorf("unexpected double encoding of 4.0 [0x%x]", doubleEnc.GetEncoding(4.0))
		return
	}
}

func TestFloatOps(t *testing.T) {
	ctx, err := CreateContext(SLEIGH_ARCH_X86_64, SLEIGH_PROC_X86_64)
	if err != nil {
		t.Error(err)
		return
	}
	defer ctx.Delete()

	floatEnc, err := ctx.GetHostFloat(4)
	if err != nil {
		t.Error(err)
		return
	}

	a := floatEnc.GetEncoding(1.0)
	b := floatEnc.GetEncoding(3.5)
	c := floatEnc.OpAdd(a, b)
	d := floatEnc.OpMult(c, b)

	r := floatEnc.GetHostFloat(d)
	if r != 15.750000 {
		t.Errorf("unexpected float result %f", r)
		return
	}
}
