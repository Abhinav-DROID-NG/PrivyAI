# API

The root package exposes `New`, `DefaultConfig`, `Engine.Process`,
`Engine.ProcessWithOptions`, `Config`, `Result`, `Finding`, tier/action
constants, policy aliases, and typed errors. Detector, policy, structured, and
redactor packages expose their documented constructors and operations.

All findings use half-open byte offsets into the original input. Raw matched
values are not stored in findings or errors.
