#include <string.h>
#include <stdio.h>
#include <uchar.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "base.h"

#ifdef RUN_UNIT_TESTS
#define XBYAK_NO_EXCEPTION 
#include "xbyak/xbyak.h"
#include "unit_tests.cpp"
#endif

static string8 LoadFile(memory_arena *Arena, string8 FilePath) {
	arena_auto_pop DeferredPop(&Temp);

	char *Path = FilePath.ToCString(&Temp);

	int FileHandle = open(Path, O_RDONLY);
	if (FileHandle < 0) return {};
	OnScopeExit(close(FileHandle));

	struct stat Stats;
	if (fstat(FileHandle, &Stats) < 0) return {};

	size_t Size = Stats.st_size;
	char8 *Buffer = (char8 *)Arena->Push(Size);

	ssize_t BytesRead = read(FileHandle, Buffer, Size);
	if (BytesRead < 0) return {};


	string8 Result(Buffer, (u32)BytesRead);
	return Result;
}

static string8 LoadPreprocessedFile(memory_arena *Arena, string8 FilePath) {
	arena_auto_pop DeferredPop(&Temp);

	char *Path = FilePath.ToCString(&Temp);

	char CommandBuffer[1024];
	snprintf(CommandBuffer, sizeof(CommandBuffer), "clang -E -P %s", Path);

	FILE *Pipe = popen(CommandBuffer, "r");
	if (!Pipe) return {};

	OnScopeExit(pclose(Pipe));

	string8 Result = {};
	const size_t ChunkSize = 4096;
	Result.Data = (char8 *)Arena->Push(0);
	Result.Length = 0;
	while (true) {
		char8 *Chunk = (char8 *)Arena->Push(ChunkSize);
		size_t BytesRead = fread(Chunk, 1, ChunkSize, Pipe);

		if (BytesRead == 0) {
			Arena->Pop(Chunk);
			break;
		}

		Result.Length += (u32)BytesRead;
	}

	return Result;
}


enum token_type : u32 {
	Identifier = 256,
	IntConstant,
	OperatorDecrement,
	OperatorIncrement,
	KeywordInt,
	KeywordVoid,
	KeywordReturn,
};

struct token {
	token_type Type;
	union {
		u32 Constant;
		string8 String;
	};
};

constexpr inline bool IsAlpha(const u8 c) {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_';
}
constexpr inline bool IsNumeric(const u8 c) {
	return c >= '0' && c <= '9';
}
constexpr inline bool IsAlphaNumeric(const u8 c) {
	return IsAlpha(c) || IsNumeric(c);
}

constexpr inline bool IsWhitespace(const u8 c) {
	return c == ' ' || c == '\r' || c == '\n' || c == '\t';
}

struct keyword_metadata {
	string8 String;
	token_type TokenType;
};

static keyword_metadata Keywords[] = {
	{ string8(u8"int"), KeywordInt },
	{ string8(u8"void"), KeywordVoid },
	{ string8(u8"return"), KeywordReturn }
};

inline token_type GetAlphaNumericType(const string8 &String) {
	for (u32 i = 0; i < ArrayLen(Keywords); ++i) {
		if (string8::AreEqual(String, Keywords[i].String)) {
			return Keywords[i].TokenType;
		}
	}

	return token_type::Identifier;
}

[[noreturn]]
void Fail(const char * Message, ...) {
	va_list Args;
	va_start(Args, Message);
	vfprintf(stderr, Message, Args);
	va_end(Args);
	fprintf(stderr, "\n");
	exit(1);
}

enum class ast_node_type : u32 {
	Invalid = 0,
	FunctionDeclaration,
	Expression,
	Identifier,
	IntConstant,
	Return,
	UnaryNegate,
	UnaryBitwiseNegate,
};

struct ast_node {
	ast_node_type Type = ast_node_type::Invalid;
	union {
		u64 IntValue;

		struct {
			ast_node *Expression;
		} ReturnStatement;

		struct {
			ast_node *Expression;
		} UnaryOperation;
	};
};

ast_node DefaultAstNode = {
	.Type = ast_node_type::Invalid
};

struct ast_function_declaration {
	string8 Name = {};
	ast_node *FunctionBody = &DefaultAstNode;
};

struct parser_state {
	memory_arena *Arena;

	linked_list<token>::iterator Current;

	const token &AdvanceToken() {
		return Current.Next();
	}
	const token &CurrentToken() {
		return *Current;
	}

	ast_node *PushReturnNode() {
		ast_node *Node = Arena->Push<ast_node>();
		Node->Type = ast_node_type::Return;
		Node->ReturnStatement.Expression = &DefaultAstNode;
		return Node;
	}

	ast_node *PushIntConstantNode(u64 Value) {
		ast_node *Node = Arena->Push<ast_node>();
		Node->Type = ast_node_type::IntConstant;
		Node->IntValue = Value;
		return Node;
	}

	ast_node *PushUnaryOperationNode(ast_node_type Type, ast_node *Expression = &DefaultAstNode) {
		assert(Type == ast_node_type::UnaryNegate || Type == ast_node_type::UnaryBitwiseNegate);
		ast_node *Node = Arena->Push<ast_node>();
		Node->Type = Type;
		Node->UnaryOperation.Expression = Expression;
		return Node;
	}
};

static void Expect(bool Condition, const char *Message) {
	if (!Condition) {
		Fail("Parse error: %s", Message);
	}
}

static bool IsUnaryOperator(token_type Type) {
	return Type == '~' || Type == '-';
}

static ast_node *Expression(parser_state *State) {

	if (State->CurrentToken().Type == '(') {
		State->AdvanceToken();
		ast_node *Node = Expression(State);
		Expect(State->CurrentToken().Type == ')', "Expected ')' to close expression");
		State->AdvanceToken();
		return Node;
	}

	if (IsUnaryOperator(State->CurrentToken().Type)) {
		ast_node_type UnaryType = (State->CurrentToken().Type == '-') ? ast_node_type::UnaryNegate : ast_node_type::UnaryBitwiseNegate;
		State->AdvanceToken();
		ast_node *Result = State->PushUnaryOperationNode(UnaryType);
		Result->UnaryOperation.Expression = Expression(State);
		return Result;
	}

	if (State->CurrentToken().Type == token_type::IntConstant) {
		u64 Value = State->CurrentToken().Constant;
		ast_node *Result = State->PushIntConstantNode(Value);
		State->AdvanceToken();
		return Result;
	}
	Fail("Expected an expression, found token type: %u", State->CurrentToken().Type);
	return &DefaultAstNode;
}

static ast_node *ParseStatement(parser_state *State) {
	Expect(State->CurrentToken().Type == token_type::KeywordReturn, "Expected 'return' keyword");
	State->AdvanceToken();

	ast_node *ReturnNode = State->PushReturnNode();
	ReturnNode->ReturnStatement.Expression = Expression(State);

	Expect(State->CurrentToken().Type == ';', "Expected ';' to end return statement");
	State->AdvanceToken();

	return ReturnNode;
}

static linked_list<ast_function_declaration> ParseProgram(parser_state *State) {
	linked_list<ast_function_declaration> FunctionList(State->Arena);

	while (State->CurrentToken().Type == token_type::KeywordInt) {
		ast_function_declaration FunctionDecl = {};

		Expect(State->CurrentToken().Type == token_type::KeywordInt, "Function must return int");
		Expect(State->AdvanceToken().Type == token_type::Identifier, "Expected identifier after 'int' keyword");
		FunctionDecl.Name = State->CurrentToken().String;

		Expect(State->AdvanceToken().Type == '(', "Expected '(' after function name");
		Expect(State->AdvanceToken().Type == token_type::KeywordVoid, "Expected 'void' for function parameters");
		Expect(State->AdvanceToken().Type == ')', "Expected ')' after function parameters");
		Expect(State->AdvanceToken().Type == '{', "Expected '{' to start function body");
		State->AdvanceToken();

		FunctionDecl.FunctionBody = ParseStatement(State);

		Expect(State->CurrentToken().Type == '}', "Expected '}' to end function body");
		State->AdvanceToken();

		FunctionList.Push(FunctionDecl);
	}

	return FunctionList;
}

static void PrettyPrintAst(ast_node *Node, u32 Indent = 0) {
	if (Node == &DefaultAstNode) return;

	for (u32 i = 0; i < Indent; ++i) {
		printf("  ");
	}

	switch (Node->Type) {
		case ast_node_type::Return:
			printf("Return Statement:\n");
			PrettyPrintAst(Node->ReturnStatement.Expression, Indent + 1);
			break;
		case ast_node_type::IntConstant:
			printf("Int Constant: %lu\n", Node->IntValue);
			break;
		case ast_node_type::UnaryNegate:
			printf("Unary Negate:\n");
			PrettyPrintAst(Node->UnaryOperation.Expression, Indent + 1);
			break;
		case ast_node_type::UnaryBitwiseNegate:
			printf("Unary Bitwise Not:\n");
			PrettyPrintAst(Node->UnaryOperation.Expression, Indent + 1);
			break;
		default:
			printf("Unknown AST node type\n");
			break;
	}

}

namespace assembly {
	enum class operation {
		Invalid,
		Mov,
		Return,
		Negate,
		BitwiseNegate,
	};
	enum class x64_register {
		Invalid,
		EAX,
		R10D,
		Count
	};
	enum class operand_type {
		Invalid,
		Immediate,
		Register,
		StackLocation,
	};
	struct operand {
		operand_type Type = operand_type::Invalid;
		union {
			u64 ImmediateValue;
			x64_register Register;
			s64 StackLocation;
		};
	};

	struct instruction {
		operation Op;
		operand Src, Dst;
	};

	struct function {
		string8 Name;
		s64 StackSize;
		linked_list<instruction> Instructions;
	};
};

struct string8_builder {
	memory_arena *Arena;

	u32 FinalStringLength = 0;
	linked_list<string8> StringList;

	string8_builder(memory_arena *InArena = &Temp) : Arena(InArena) {
		StringList = linked_list<string8>(Arena);
	}

	void Push(const string8 &InString) {
		StringList.Push(InString);
		FinalStringLength += InString.Length;
	}

	void operator += (const string8 &InString) {
		Push(InString);
	}

	string8_builder operator + (const string8 &InString) {
		Push(InString);
		return *this;
	}

	void operator += (const u64 Value) {
		string8 String = string8::FromUnsignedInt(Arena, Value);
		Push(String);
	}
	void operator += (const s64 Value) {
		string8 String = string8::FromSignedInt(Arena, Value);
		Push(String);
	}

	void Combine(string8_builder &Other) {
		this->StringList.Tail->Next = Other.StringList.Head->Next;
		this->StringList.Tail = Other.StringList.Tail;
		FinalStringLength += Other.FinalStringLength;

		Other.StringList.Head->Next = &linked_list<string8>::SentinelNode;
		Other.FinalStringLength = 0;
	}

	void operator += (string8_builder &Other) {
		Combine(Other);
	}
	void operator += (string8_builder &&Other) {
		Combine(Other);
	}

	string8 FinalizeString() {
		char8 *Buffer = (char8 *)Arena->Push(FinalStringLength);

		char8 *BufferEnd = Buffer;

		for (const string8 &String : StringList) {
			memcpy(BufferEnd, String.Data, String.Length);
			BufferEnd += String.Length;
		}

		u64 CalculatedLength = BufferEnd - Buffer;
		assert(CalculatedLength == FinalStringLength);

		return string8(Buffer, FinalStringLength);
	}
};

string8_builder string8::operator + (const string8 &Other) {
	string8_builder Builder(&Temp);
	Builder.Push(*this);
	Builder.Push(Other);
	return Builder;
}

constexpr string8 RegisterToString(assembly::x64_register Register) {
	switch (Register) {
		case assembly::x64_register::EAX: {
			return string8(u8"%eax");
		} break;
		case assembly::x64_register::R10D: {
			return string8(u8"%r10d");
		} break;
	}

	return {};
}

static void EmitMovInstruction(string8_builder &Builder, const assembly::operand &Src, const assembly::operand &Dst) {
	if (Src.Type == assembly::operand_type::StackLocation && Dst.Type == assembly::operand_type::StackLocation) {
		Builder += string8(u8"  movl ") + Src.StackLocation + u8"(%rbp), %r10d\n";
		Builder += string8(u8"  %r10, ") + Dst.StackLocation + u8"(%rbp)\n";
		return;
	}

	if (Src.Type == assembly::operand_type::Immediate) {
		Builder += string8(u8"  movl $") + Src.ImmediateValue + u8", ";
		switch (Dst.Type) {
			case assembly::operand_type::Register: {
				Builder += RegisterToString(Dst.Register) + u8"\n";
				return;
			} break;
			case assembly::operand_type::StackLocation: {
				Builder += string8(Dst.StackLocation) + u8"(%rbp)\n";
				return;
			} break;
		}
	}

	if (Src.Type == assembly::operand_type::Register) {

		if (Dst.Type == assembly::operand_type::Register) {
			if (Src.Register == Dst.Register) return;
		}

		Builder += string8(u8"  movl ") + RegisterToString(Src.Register) + u8", ";
		switch (Dst.Type) {
			case assembly::operand_type::Register: {
				Builder += RegisterToString(Dst.Register) + u8"\n";
				return;
			} break;
			case assembly::operand_type::StackLocation: {
				Builder += string8(Dst.StackLocation) + u8"(%rbp)\n";
				return;
			} break;
		}
	}

	if (Src.Type == assembly::operand_type::StackLocation) {
		Builder += string8(u8"  movl ") + Src.StackLocation + u8"(%rbp), ";
		switch (Dst.Type) {
			case assembly::operand_type::Register: {
				Builder += RegisterToString(Dst.Register) + u8"\n";
				return;
			} break;
		}
	}

	assert(false);
}

using main_function_type = s32(*)();

#ifdef RUN_UNIT_TESTS
static void LiveJITAssembly(assembly::function *Function, Xbyak::CodeGenerator &x64) {
	arena_auto_pop DeferredPop(&Temp);

	using namespace Xbyak;
	using namespace Xbyak::util;

	if (Function->StackSize > 0) {
		x64.push(rbp);
		x64.mov(rbp, rsp);
	}

	const auto EmitMovInstruction = [&x64](assembly::operand Src, assembly::operand Dst) {
		if (Src.Type == assembly::operand_type::StackLocation && Dst.Type == assembly::operand_type::StackLocation) {
			x64.mov(r10d, dword[rbp + Src.StackLocation]);
			x64.mov(dword[rbp + Dst.StackLocation], r10d);
			return;
		}

		Reg32 X64Registers[(u32)assembly::x64_register::Count];
		X64Registers[(u32)assembly::x64_register::EAX] = eax;
		X64Registers[(u32)assembly::x64_register::R10D] = r10d;

		if (Src.Type == assembly::operand_type::Immediate && Dst.Type == assembly::operand_type::Register) {
			Reg32 Register = X64Registers[(u32)Dst.Register];
			x64.mov(Register, (u32)Src.ImmediateValue);
			return;
		}
		if (Src.Type == assembly::operand_type::StackLocation && Dst.Type == assembly::operand_type::Register) {
			Reg32 DstRegister = X64Registers[(u32)Dst.Register];
			x64.mov(DstRegister, dword[rbp + Src.StackLocation]);
			return;
		}
		if (Src.Type == assembly::operand_type::Register && Dst.Type == assembly::operand_type::StackLocation) {
			Reg32 SrcRegister = X64Registers[(u32)Src.Register];
			x64.mov(dword[rbp + Dst.StackLocation], SrcRegister);
			return;
		}

		assert(false);
	};

	constexpr assembly::operand EAX = { .Type = assembly::operand_type::Register, .Register = assembly::x64_register::EAX };

	for (const assembly::instruction &Instruction : Function->Instructions) {
		switch (Instruction.Op) {
			case assembly::operation::Mov: {
				EmitMovInstruction(Instruction.Src, Instruction.Dst);
			} break;
			case assembly::operation::BitwiseNegate: {
				EmitMovInstruction(Instruction.Src, EAX);
				x64.not(eax);
				EmitMovInstruction(EAX, Instruction.Dst);
			} break;
			case assembly::operation::Negate: {
				EmitMovInstruction(Instruction.Src, EAX);
				x64.neg(eax);
				EmitMovInstruction(EAX, Instruction.Dst);
			} break;
			case assembly::operation::Return: {
				EmitMovInstruction(Instruction.Src, EAX);
				if (Function->StackSize > 0) {
					x64.mov(rsp, rbp);
					x64.pop(rbp);
				}
				x64.ret();
			} break;
		}
	}
}
#endif

static void EmitAssemblyToFile(assembly::function *Function, const string8 &FilePath) {
	arena_auto_pop DeferredPop(&Temp);

	char *Path = FilePath.ToCString(&Temp);
	s32 FileDescriptor = open(Path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (FileDescriptor < 0) {
		Fail("Failed to open file for writing: %s", Path);
	}
	OnScopeExit(close(FileDescriptor));

	string8_builder Builder(&Temp);
	Builder += u8".global main\n"
			   u8"main:\n";

	if (Function->StackSize > 0) {
		Builder += u8"  pushq %rbp\n"
					u8"  movq %rsp, %rbp\n";
		Builder += string8(u8"  subq  $") + Function->StackSize + u8", %rsp\n";
	}

	const assembly::operand EAX = { .Type = assembly::operand_type::Register, .Register = assembly::x64_register::EAX };

	for (const assembly::instruction &Instruction : Function->Instructions) {
		switch (Instruction.Op) {
			case assembly::operation::Mov: {
				EmitMovInstruction(Builder, Instruction.Src, Instruction.Dst);
			} break;
			case assembly::operation::BitwiseNegate: {
				EmitMovInstruction(Builder, Instruction.Src, EAX);
				Builder += u8"  not %eax\n";
				EmitMovInstruction(Builder, EAX, Instruction.Dst);
			} break;
			case assembly::operation::Negate: {
				EmitMovInstruction(Builder, Instruction.Src, EAX);
				Builder += u8"  neg %eax\n";
				EmitMovInstruction(Builder, EAX, Instruction.Dst);
			} break;
			case assembly::operation::Return: {
				EmitMovInstruction(Builder, Instruction.Src, Instruction.Dst);
				if (Function->StackSize > 0) {
					Builder += u8"  movq %rbp, %rsp\n"
							u8"  popq %rbp\n";
				}
				Builder += u8"  ret\n";
			} break;
			default:
				break;
		}
	}

	Builder += u8".section .note.GNU-stack,\"\", @progbits\n";

	string8 FinalString = Builder.FinalizeString();
	ssize_t BytesWritten = write(FileDescriptor, FinalString.Data, FinalString.Length);
	if (BytesWritten < 0) {
		Fail("Failed to write to file: %s", Path);
	}
}

namespace ir {
	struct operand {
		enum class type {
			Invalid,
			Temp,
			Constant
		};
		type Type = type::Invalid;
		u64 Value;
	};

	struct instruction {
		enum class opcode {
			Invalid,
			Return,
			Negate,
			BitwiseNegate
		};
		opcode Opcode;
		operand Dst, Src1, Src2;
	};

	struct function {
		string8 Name;
		linked_list<instruction> Instructions;
		u64 TempCount = 0;
	};
};

static ir::operand EmitExpressionIR(ir::function *Function, ast_node *ExpressionNode) {
	switch (ExpressionNode->Type) {
		case ast_node_type::IntConstant: {
			return { ir::operand::type::Constant, ExpressionNode->IntValue };
		} break;
		case ast_node_type::UnaryNegate:
		case ast_node_type::UnaryBitwiseNegate: {
			ir::operand Src = EmitExpressionIR(Function, ExpressionNode->UnaryOperation.Expression);
			ir::operand Dst = { ir::operand::type::Temp, Function->TempCount++ };
			ir::instruction::opcode Opcode = (ExpressionNode->Type == ast_node_type::UnaryNegate)
				? ir::instruction::opcode::Negate : ir::instruction::opcode::BitwiseNegate;
			ir::instruction NewInstruction = { .Opcode = Opcode, .Dst = Dst, .Src1 = Src, };
			Function->Instructions.Push(NewInstruction);
			return Dst;
		} break;
		default:;
	}

	return {};
}

static ir::function EmitIR(memory_arena *Arena, const linked_list<ast_function_declaration> &Node) {
	const ast_function_declaration &FunctionDecl = *Node.begin();

	ir::function Result;
	Result.Name = FunctionDecl.Name;
	Result.Instructions = linked_list<ir::instruction>(Arena);
	Result.TempCount = 0;

	ir::operand Operand = EmitExpressionIR(&Result, FunctionDecl.FunctionBody->ReturnStatement.Expression);
	ir::instruction ReturnInstruction = {
		.Opcode = ir::instruction::opcode::Return,
		.Src1 = Operand
	};
	Result.Instructions.Push(ReturnInstruction);

	return Result;
}

static assembly::operand IROperandToAssemblyOperand(const ir::operand &IROperand) {
	assembly::operand Result = {};
	switch (IROperand.Type) {
		case ir::operand::type::Constant: {
			Result.Type = assembly::operand_type::Immediate;
			Result.ImmediateValue = IROperand.Value;
		} break;
		case ir::operand::type::Temp: {
			Result.Type = assembly::operand_type::StackLocation;
			Result.StackLocation = -(s64)IROperand.Value * 4 - 4;
		} break;
	}
	return Result;
}

static void PrintAssemblyInstructions(const assembly::function &Function) {
	arena_auto_pop DeferredPop(&Temp);

	auto PrintOperand = [&](const assembly::operand &Op, string8_builder &Builder) {
		switch (Op.Type) {
			case assembly::operand_type::Immediate: {
				Builder += u8"$";
				Builder += Op.ImmediateValue;
			} break;
			case assembly::operand_type::Register:
				switch (Op.Register) {
					case assembly::x64_register::EAX: Builder += u8"%rax"; break;
					case assembly::x64_register::R10D: Builder += u8"%r10"; break;
				} break;
			case assembly::operand_type::StackLocation: {
				Builder += Op.StackLocation;
				Builder += u8"(%rsp)";
			} break;
			default:;
		}
	};

	string8_builder Builder(&Temp);
	for (const assembly::instruction &Instruction : Function.Instructions) {
		switch (Instruction.Op) {
			case assembly::operation::Negate: {
				Builder += u8"negate ";
				PrintOperand(Instruction.Src, Builder);
				Builder += u8" -> ";
				PrintOperand(Instruction.Dst, Builder);
				Builder += u8"\n";
			} break;
			case assembly::operation::BitwiseNegate: {
				Builder += u8"bitwise_negate ";
				PrintOperand(Instruction.Src, Builder);
				Builder += u8" -> ";
				PrintOperand(Instruction.Dst, Builder);
				Builder += u8"\n";
			} break;
			case assembly::operation::Return: {
				Builder += u8"return ";
				PrintOperand(Instruction.Src, Builder);
				Builder += u8" -> ";
				PrintOperand(Instruction.Dst, Builder);
				Builder += u8"\n";
			} break;
			default: {
			} break;
		}
	}
	string8::Print(Builder.FinalizeString());
}

static assembly::function IRFunctionToAssembly(memory_arena *Arena, const ir::function &Function) {
	assembly::function Result;
	Result.Instructions = linked_list<assembly::instruction>(Arena);
	Result.Name = Function.Name;
	Result.StackSize = Function.TempCount * 8;

	for (const ir::instruction &Instruction : Function.Instructions) {
		assembly::instruction AssemblyInstruction = {};
		switch (Instruction.Opcode) {
			case ir::instruction::opcode::Negate: {
				AssemblyInstruction.Op = assembly::operation::Negate;
				AssemblyInstruction.Src = IROperandToAssemblyOperand(Instruction.Src1);
				AssemblyInstruction.Dst = IROperandToAssemblyOperand(Instruction.Dst);
			} break;
			case ir::instruction::opcode::BitwiseNegate: {
				AssemblyInstruction.Op = assembly::operation::BitwiseNegate;
				AssemblyInstruction.Src = IROperandToAssemblyOperand(Instruction.Src1);
				AssemblyInstruction.Dst = IROperandToAssemblyOperand(Instruction.Dst);
			} break;
			case ir::instruction::opcode::Return: {
				AssemblyInstruction.Op = assembly::operation::Return;
				AssemblyInstruction.Dst = { .Type = assembly::operand_type::Register, .Register = assembly::x64_register::EAX };
				AssemblyInstruction.Src = IROperandToAssemblyOperand(Instruction.Src1);
			} break;
			default: {
				continue;
			}
		}
		Result.Instructions.Push(AssemblyInstruction);
	}

#if 0
	PrintAssemblyInstructions(Result);
#endif

	return Result;
}

linked_list<token> Tokenize(memory_arena *Arena, const string8 &FileContents) {

	linked_list<token> TokenList(Arena);

	char8 CharTable[256] = {0};
	CharTable['('] = 1;
	CharTable[')'] = 1;
	CharTable['{'] = 1;
	CharTable['}'] = 1;
	CharTable[';'] = 1;
	CharTable['~'] = 1;
	CharTable['-'] = 1;
	CharTable['+'] = 1;

	u32 LineNumber = 1;
	u32 LastNewLineIndex = 0;

	for (u32 i = 0; i < FileContents.Length;) {
		char8 c = FileContents[i];

		if (IsWhitespace(c)) {
			if (c == '\n') LineNumber += 1;
			i += 1;
			LastNewLineIndex = i;
			continue;
		}

		if (IsAlpha(c)) {
			u32 StartIndex = i;
			do {
				i += 1;
			} while (IsAlphaNumeric(FileContents[i]));

			if (!IsWhitespace(FileContents[i]) && !CharTable[FileContents[i]]) {
				Fail("Invalid identifier or keyword at index %u: '%c' (line %u)", i - LastNewLineIndex, FileContents[i], LineNumber);
			}
			string8 IdentifierOrKeyword = FileContents.Substring(StartIndex, i);
			token_type Type = GetAlphaNumericType(IdentifierOrKeyword);

			token *NewToken = TokenList.Push({ Type });
			NewToken->String = IdentifierOrKeyword;
			continue;
		}

		if (IsNumeric(c)) {
			u32 StartIndex = i;

			do {
				i += 1;
			} while (IsNumeric(FileContents[i]));

			if (IsAlpha(FileContents[i]) || FileContents[i] == '_') {
				Fail("Invalid numeric constant at index %u: '%c' (line %u)", i - LastNewLineIndex, FileContents[i], LineNumber);
			}
			if (!IsWhitespace(FileContents[i]) && !CharTable[FileContents[i]]) {
				Fail("Invalid numeric constant at index %u: '%c' (line %u)", i - LastNewLineIndex, FileContents[i], LineNumber);
			}

			u32 Value = 0;
			const u32 EndIndex = i;
			for (u32 Index = StartIndex; Index < EndIndex; ++Index) {
				Value *= 10;
				Value += FileContents[Index] - '0';
			}

			token *NewToken = TokenList.Push({ token_type::IntConstant });
			NewToken->Constant = Value;
			continue;
		}

		if (c == '-') {
			if (FileContents[i + 1] == '-') {
				token *NewToken = TokenList.Push({ token_type::OperatorDecrement });
				i += 2;
				continue;
			}
		}

		if (c == '+') {
			if (FileContents[i + 1] == '+') {
				token *NewToken = TokenList.Push({ token_type::OperatorIncrement });
				i += 2;
				continue;
			}
		}

		if (CharTable[c]) {
			token *NewToken = TokenList.Push({ (token_type)c });
			i += 1;
			continue;
		}

		Fail("Unexpected character '%c' at index %u (line %u)", c, i - LastNewLineIndex, LineNumber);
	}

	return TokenList;
};

void CompileFile(string8 FilePath) {
	memory_arena Arena = {};
	Arena.Init(MB(256));
	OnScopeExit(Temp.Reset());

	string8 FileContents = LoadPreprocessedFile(&Arena, FilePath);
	linked_list<token> TokenList = Tokenize(&Arena, FileContents);

	parser_state ParserState = {
		.Arena = &Arena,
		.Current = TokenList.begin()
	};
	linked_list<ast_function_declaration> FunctionList = ParseProgram(&ParserState);
	ir::function IRFunction = EmitIR(&Arena, FunctionList);
	assembly::function AssemblyFunction = IRFunctionToAssembly(&Arena, IRFunction);

	constexpr string8 OutputFileName = string8(u8"output.s");
	EmitAssemblyToFile(&AssemblyFunction, OutputFileName);
}

#ifdef RUN_UNIT_TESTS
void CompileUnitTest(string8 SourceCode, s32 ExpectedResult) {
	memory_arena Arena = {};
	Arena.Init(MB(256));
	OnScopeExit(Temp.Reset());

	linked_list<token> TokenList = Tokenize(&Arena, SourceCode);
	
	parser_state ParserState = {
		.Arena = &Arena,
		.Current = TokenList.begin()
	};
	linked_list<ast_function_declaration> FunctionList = ParseProgram(&ParserState);
	ir::function IRFunction = EmitIR(&Arena, FunctionList);
	assembly::function AssemblyFunction = IRFunctionToAssembly(&Arena, IRFunction);

	Xbyak::CodeGenerator CodeGenerator;
	LiveJITAssembly(&AssemblyFunction, CodeGenerator);

	main_function_type Main = CodeGenerator.getCode<main_function_type>();
	s32 Result = Main();
	if (Result != ExpectedResult) {
		char *SourceCodeCString = SourceCode.ToCString(&Arena);
		printf("\n%s\nExpected: %d\nReturned: %d\n", SourceCodeCString, ExpectedResult, Result);
		assert(ExpectedResult == Result);
	}
}
#endif

s32 main(s32 argc, char **argv) {

	Temp.Init(MB(64));

	constexpr string8 RunUnitTestsCommand = u8"--unit-tests";

	#if RUN_UNIT_TESTS
	constexpr bool UnitTestsEnabled = true;
	#else
	constexpr bool UnitTestsEnabled = false;
	#endif

	bool ExecuteUnitTests = false;

	string8 FilePath;

	for (s32 i = 1; i < argc; ++i) {
		string8 CommandLineArgument = (char8 *)argv[i];
		if (UnitTestsEnabled && string8::AreEqual(RunUnitTestsCommand, CommandLineArgument)) {
			ExecuteUnitTests = true;
			continue;
		}

		if (CommandLineArgument.EndsWith(u8".c")) {
			FilePath = CommandLineArgument;
			continue;
		}
	}

	if (!ExecuteUnitTests && FilePath.Length == 0) {
		Fail("No input file provided");
	}

#ifdef RUN_UNIT_TESTS
	if (ExecuteUnitTests && ExecuteUnitTests) {
		printf("Running Unit Tests...\n");
		for (const unit_test &UnitTest : UnitTestsPass) {
			CompileUnitTest(UnitTest.SourceCode, UnitTest.ExpectedResult);
		}
		puts(ANSI_GREEN "All unit tests passed!\n" ANSI_RESET);
	}
#endif

	if (FilePath.Length > 0) {
		printf("Compiling File: %s\n\n", (char *)FilePath.Data);
		CompileFile(FilePath);
	}

	return 0;
}
