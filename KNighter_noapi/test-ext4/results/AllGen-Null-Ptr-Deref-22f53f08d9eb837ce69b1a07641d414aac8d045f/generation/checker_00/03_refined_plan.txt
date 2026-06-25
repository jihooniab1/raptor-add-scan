```
1. **Register Program State Map:**
   - Use `REGISTER_MAP_WITH_PROGRAMSTATE(EarlyAssignMap, const MemRegion*, const Stmt*)`
     to map a field region (e.g. the `priv` member of `test`) to the statement
     where the early assignment happened. The `Stmt*` is kept only for use in
     the bug report.

2. **Track Suspicious Field Assignments (`checkBind`):**
   - Trigger only when `Loc` corresponds to a `FieldRegion` whose underlying
     field is of pointer type (a "context/private" pointer such as
     `test->priv`).
   - Ignore assignments where `Val` is a known null pointer
     (`Val.isZeroConstant()` or `isa<loc::ConcreteInt>` with value 0). NULL
     stores are how cleanup happens, so they should remove the entry from
     `EarlyAssignMap` instead of adding one.
   - For non-null assignments, retrieve the binding statement `S` and store
     `(FieldRegion, S)` into `EarlyAssignMap`. This captures the "early
     assignment" suspicion; the symbolic-execution engine will explore later
     paths from this state.

3. **Detect Error-Return Paths (`checkPreStmt` on `ReturnStmt`):**
   - Obtain the return expression. If it is missing, do nothing.
   - Use `EvaluateExprToInt` to try to evaluate the returned value as a
     concrete integer. If it evaluates to a non-zero value (typical error
     code, e.g. `-ENOMEM`, `-12`, any negative or positive non-zero int),
     treat this as an error-return path.
   - Iterate over every entry in `EarlyAssignMap`. For each remaining
     `(FieldRegion, AssignStmt)` pair, this means the context pointer was
     written but never cleared before this error return: call
     `reportEarlyAssign(C, FieldRegion, AssignStmt)`.
   - To reduce noise, also confine the check to functions that look like an
     init routine (return type is `int` and the surrounding `FunctionDecl`'s
     name contains "init" or "probe"). Get the `FunctionDecl` via
     `C.getLocationContext()->getDecl()` and use `getNameAsString()` for the
     name match. This keeps reports focused on the init/cleanup pairing
     pattern described.

4. **Drop Stale Entries on Successful Completion:**
   - In the same `checkPreStmt(ReturnStmt)` handler, if the returned value
     evaluates to `0` (success), simply do nothing: those entries are correct
     final assignments, and analysis of this path ends here.
   - In `checkBind`, when the bound value is null, call
     `State->remove<EarlyAssignMap>(FieldRegion)` and `addTransition(State)`
     so that an explicit `test->priv = NULL;` before the error return
     suppresses the warning.

5. **Bug Reporting (`reportEarlyAssign`):**
   - Generate a non-fatal error node via `C.generateNonFatalErrorNode()`.
   - Construct a `std::make_unique<PathSensitiveBugReport>` with a short
     message such as: "Context pointer assigned before initialization
     completed; cleanup may dereference partially-initialized state."
   - Attach the source range of the stored `AssignStmt` to the report via
     `addRange()` to point users at the premature assignment, and emit it
     with `C.emitReport(std::move(Report))`.
```