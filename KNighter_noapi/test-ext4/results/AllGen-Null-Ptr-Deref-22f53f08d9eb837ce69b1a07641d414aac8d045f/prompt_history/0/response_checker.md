```cpp
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Map a field region (e.g. test->priv) to the Stmt where the early
// (non-null) assignment was made. The Stmt is used to enrich bug reports.
REGISTER_MAP_WITH_PROGRAMSTATE(EarlyAssignMap, const MemRegion *, const Stmt *)

namespace {

class SAGenTestChecker
    : public Checker<check::Bind, check::PreStmt<ReturnStmt>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Context pointer assigned before init completed",
                       "Memory Error")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;

private:
  void reportEarlyAssign(CheckerContext &C, const MemRegion *FR,
                         const Stmt *AssignStmt) const;
  bool isInitLikeFunction(CheckerContext &C) const;
};

bool SAGenTestChecker::isInitLikeFunction(CheckerContext &C) const {
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return false;
  const Decl *D = LCtx->getDecl();
  const auto *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return false;

  // Should be an int-returning function (typical init/probe pattern).
  QualType RT = FD->getReturnType();
  if (!RT->isIntegerType())
    return false;

  std::string Name = FD->getNameAsString();
  if (Name.find("init") != std::string::npos)
    return true;
  if (Name.find("probe") != std::string::npos)
    return true;
  return false;
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  // Only care about field regions of pointer-typed fields.
  const auto *FR = dyn_cast<FieldRegion>(MR);
  if (!FR)
    return;

  const FieldDecl *FD = FR->getDecl();
  if (!FD)
    return;

  QualType FT = FD->getType();
  if (!FT->isPointerType())
    return;

  // If the bound value is null, remove any prior entry: an explicit
  // clear before returning is a correct pattern.
  if (Val.isZeroConstant()) {
    if (State->get<EarlyAssignMap>(FR)) {
      State = State->remove<EarlyAssignMap>(FR);
      C.addTransition(State);
    }
    return;
  }

  // Record this non-null assignment as a "potentially early" one. If the
  // function returns successfully, we will simply not warn on that path.
  State = State->set<EarlyAssignMap>(FR, S);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS,
                                    CheckerContext &C) const {
  if (!RS)
    return;

  // Restrict to init-like functions to reduce false positives.
  if (!isInitLikeFunction(C))
    return;

  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;

  ProgramStateRef State = C.getState();

  // Try to evaluate the return value as a concrete integer.
  llvm::APSInt RetVal;
  if (!EvaluateExprToInt(RetVal, RetE, C))
    return;

  // Successful return: nothing to report on this path.
  if (RetVal == 0)
    return;

  // Error return: any still-recorded early assignment is suspicious.
  EarlyAssignMapTy Map = State->get<EarlyAssignMap>();
  if (Map.isEmpty())
    return;

  for (auto I = Map.begin(), E = Map.end(); I != E; ++I) {
    const MemRegion *FR = I->first;
    const Stmt *AssignStmt = I->second;
    reportEarlyAssign(C, FR, AssignStmt);
  }
}

void SAGenTestChecker::reportEarlyAssign(CheckerContext &C,
                                         const MemRegion *FR,
                                         const Stmt *AssignStmt) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Context pointer assigned before initialization completed; "
      "cleanup may dereference partially-initialized state",
      N);
  if (AssignStmt)
    Report->addRange(AssignStmt->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects context/private pointer assigned before init completes, "
      "where a later error return leaves cleanup to dereference a "
      "partially-initialized object",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```