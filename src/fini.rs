use crate::debugger::DebuggerInfo;


pub fn fini(debugger_info: &DebuggerInfo) {
    debugger_info.vm_watchpoint_manager.delete_all(debugger_info.debug_info.target_pid());
}