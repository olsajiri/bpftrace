#pragma once

#include "ast.h"
#include "bpftrace.h"
#include <llvm/IR/DIBuilder.h>

namespace bpftrace {
namespace ast {

using namespace llvm;

class DIBuilderBPF : public DIBuilder
{
public:
  DIBuilderBPF(Module &module);

  void CreateCompileUnit(void);
  void CreateFunction(Function *func, const std::string &name,
                      size_t pointer_size);
  void Finalize(void);

private:
  DISubroutineType* createFunctionType(size_t pointer_size);

  DICompileUnit *cu_;
};

} // namespace ast
} // namespace bpftrace
