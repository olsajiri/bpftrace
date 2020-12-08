#include <iostream>
#include <sstream>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include "dibuilderbpf.h"
#include <dwarf.h>

namespace bpftrace {
namespace ast {

DIBuilderBPF::DIBuilderBPF(Module &module)
  : DIBuilder(module) { }

void DIBuilderBPF::CreateCompileUnit(void)
{
  cu_ = createCompileUnit(dwarf::DW_LANG_C,
                          createFile("fib.ks", "."),
                          "bpftrace", 0, "", 0);
}

DISubroutineType* DIBuilderBPF::createFunctionType(size_t pointer_size)
{
  DIType *arg1 = createBasicType("int", 64, DW_ATE_unsigned);
  DIType *arg2 = createPointerType(arg1, pointer_size);
  SmallVector<Metadata *, 2> args;

  args.push_back(arg1);
  args.push_back(arg2);
  return createSubroutineType(getOrCreateTypeArray(args));
}

void DIBuilderBPF::CreateFunction(Function *func, const std::string &name,
                                  size_t pointer_size)
{
  DIFile *Unit = createFile(cu_->getFilename(), cu_->getDirectory());
  unsigned LineNo = 0;
  unsigned ScopeLine = 0;
  DIScope *FContext = Unit;

  DISubprogram *SP = createFunction(
      FContext, name, name, Unit, LineNo,
      createFunctionType(pointer_size), ScopeLine,
      DINode::FlagPrototyped, DISubprogram::SPFlagDefinition);
  func->setSubprogram(SP);
}

void DIBuilderBPF::Finalize(void)
{
  finalize();
}

} // namespace ast
} // namespace bpftrace
