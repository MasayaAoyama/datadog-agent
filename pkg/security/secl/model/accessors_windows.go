//go:build windows
// +build windows

// Code generated - DO NOT EDIT.
package model

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"reflect"
)

func (m *Model) GetIterator(field eval.Field) (eval.Iterator, error) {
	switch field {
	}
	return nil, &eval.ErrIteratorNotSupported{Field: field}
}
func (m *Model) GetEventTypes() []eval.EventType {
	return []eval.EventType{
		eval.EventType("exec"),
		eval.EventType("exit"),
	}
}
func (m *Model) GetEvaluator(field eval.Field, regID eval.RegisterID) (eval.Evaluator, error) {
	switch field {
	case "exec.args":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgs(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exec.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgsFlags(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgsOptions(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgsTruncated(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgv(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exec.argv0":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgv0(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exec.cap_effective":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.CapEffective)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.cap_permitted":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.CapPermitted)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.comm":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.Comm
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.container.id":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.ContainerID
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.cookie":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Cookie)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.created_at":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveProcessCreatedAt(ev, ev.Exec.Process))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.egid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.EGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.egroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.Credentials.EGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessEnvp(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessEnvs(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessEnvsTruncated(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.euid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.EUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.euser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.Credentials.EUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exec.Process.FileEvent.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exec.Process.FileEvent.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exec.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return false
				}
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exec.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exec.Process.FileEvent.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exec.Process.FileEvent.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exec.Process.FileEvent.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exec.Process.FileEvent.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exec.Process.FileEvent.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exec.Process.FileEvent.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exec.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.fsgid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.FSGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.fsgroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.Credentials.FSGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.fsuid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.FSUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.fsuser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.Credentials.FSUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.Credentials.Group
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exec.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return false
				}
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.LinuxBinprm.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exec.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exec.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exec.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.LinuxBinprm.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.is_kworker":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.PIDContext.IsKworker
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.is_thread":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.IsThread
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.pid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.PIDContext.Pid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.ppid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.PPid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.tid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.PIDContext.Tid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.tty_name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.TTYName
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.Credentials.User
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.args":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgs(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exit.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgsFlags(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgsOptions(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgsTruncated(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgv(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exit.argv0":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgv0(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exit.cap_effective":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.CapEffective)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.cap_permitted":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.CapPermitted)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.cause":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Cause)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.code":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Code)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.comm":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.Comm
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.container.id":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.ContainerID
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.cookie":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Cookie)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.created_at":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveProcessCreatedAt(ev, ev.Exit.Process))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.egid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.EGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.egroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.Credentials.EGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessEnvp(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessEnvs(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessEnvsTruncated(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.euid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.EUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.euser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.Credentials.EUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exit.Process.FileEvent.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exit.Process.FileEvent.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exit.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return false
				}
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exit.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exit.Process.FileEvent.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exit.Process.FileEvent.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exit.Process.FileEvent.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exit.Process.FileEvent.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exit.Process.FileEvent.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exit.Process.FileEvent.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exit.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.fsgid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.FSGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.fsgroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.Credentials.FSGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.fsuid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.FSUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.fsuser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.Credentials.FSUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.Credentials.Group
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exit.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return false
				}
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.LinuxBinprm.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exit.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exit.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exit.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.LinuxBinprm.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.is_kworker":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.PIDContext.IsKworker
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.is_thread":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.IsThread
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.pid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.PIDContext.Pid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.ppid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.PPid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.tid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.PIDContext.Tid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.tty_name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.TTYName
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.Credentials.User
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	}
	return nil, &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) GetFields() []eval.Field {
	return []eval.Field{
		"exec.args",
		"exec.args_flags",
		"exec.args_options",
		"exec.args_truncated",
		"exec.argv",
		"exec.argv0",
		"exec.cap_effective",
		"exec.cap_permitted",
		"exec.comm",
		"exec.container.id",
		"exec.cookie",
		"exec.created_at",
		"exec.egid",
		"exec.egroup",
		"exec.envp",
		"exec.envs",
		"exec.envs_truncated",
		"exec.euid",
		"exec.euser",
		"exec.file.change_time",
		"exec.file.filesystem",
		"exec.file.gid",
		"exec.file.group",
		"exec.file.in_upper_layer",
		"exec.file.inode",
		"exec.file.mode",
		"exec.file.modification_time",
		"exec.file.mount_id",
		"exec.file.name",
		"exec.file.name.length",
		"exec.file.package.name",
		"exec.file.package.source_version",
		"exec.file.package.version",
		"exec.file.path",
		"exec.file.path.length",
		"exec.file.rights",
		"exec.file.uid",
		"exec.file.user",
		"exec.fsgid",
		"exec.fsgroup",
		"exec.fsuid",
		"exec.fsuser",
		"exec.gid",
		"exec.group",
		"exec.interpreter.file.change_time",
		"exec.interpreter.file.filesystem",
		"exec.interpreter.file.gid",
		"exec.interpreter.file.group",
		"exec.interpreter.file.in_upper_layer",
		"exec.interpreter.file.inode",
		"exec.interpreter.file.mode",
		"exec.interpreter.file.modification_time",
		"exec.interpreter.file.mount_id",
		"exec.interpreter.file.name",
		"exec.interpreter.file.name.length",
		"exec.interpreter.file.package.name",
		"exec.interpreter.file.package.source_version",
		"exec.interpreter.file.package.version",
		"exec.interpreter.file.path",
		"exec.interpreter.file.path.length",
		"exec.interpreter.file.rights",
		"exec.interpreter.file.uid",
		"exec.interpreter.file.user",
		"exec.is_kworker",
		"exec.is_thread",
		"exec.pid",
		"exec.ppid",
		"exec.tid",
		"exec.tty_name",
		"exec.uid",
		"exec.user",
		"exit.args",
		"exit.args_flags",
		"exit.args_options",
		"exit.args_truncated",
		"exit.argv",
		"exit.argv0",
		"exit.cap_effective",
		"exit.cap_permitted",
		"exit.cause",
		"exit.code",
		"exit.comm",
		"exit.container.id",
		"exit.cookie",
		"exit.created_at",
		"exit.egid",
		"exit.egroup",
		"exit.envp",
		"exit.envs",
		"exit.envs_truncated",
		"exit.euid",
		"exit.euser",
		"exit.file.change_time",
		"exit.file.filesystem",
		"exit.file.gid",
		"exit.file.group",
		"exit.file.in_upper_layer",
		"exit.file.inode",
		"exit.file.mode",
		"exit.file.modification_time",
		"exit.file.mount_id",
		"exit.file.name",
		"exit.file.name.length",
		"exit.file.package.name",
		"exit.file.package.source_version",
		"exit.file.package.version",
		"exit.file.path",
		"exit.file.path.length",
		"exit.file.rights",
		"exit.file.uid",
		"exit.file.user",
		"exit.fsgid",
		"exit.fsgroup",
		"exit.fsuid",
		"exit.fsuser",
		"exit.gid",
		"exit.group",
		"exit.interpreter.file.change_time",
		"exit.interpreter.file.filesystem",
		"exit.interpreter.file.gid",
		"exit.interpreter.file.group",
		"exit.interpreter.file.in_upper_layer",
		"exit.interpreter.file.inode",
		"exit.interpreter.file.mode",
		"exit.interpreter.file.modification_time",
		"exit.interpreter.file.mount_id",
		"exit.interpreter.file.name",
		"exit.interpreter.file.name.length",
		"exit.interpreter.file.package.name",
		"exit.interpreter.file.package.source_version",
		"exit.interpreter.file.package.version",
		"exit.interpreter.file.path",
		"exit.interpreter.file.path.length",
		"exit.interpreter.file.rights",
		"exit.interpreter.file.uid",
		"exit.interpreter.file.user",
		"exit.is_kworker",
		"exit.is_thread",
		"exit.pid",
		"exit.ppid",
		"exit.tid",
		"exit.tty_name",
		"exit.uid",
		"exit.user",
	}
}
func (ev *Event) GetFieldValue(field eval.Field) (interface{}, error) {
	switch field {
	case "exec.args":
		return ev.FieldHandlers.ResolveProcessArgs(ev, ev.Exec.Process), nil
	case "exec.args_flags":
		return ev.FieldHandlers.ResolveProcessArgsFlags(ev, ev.Exec.Process), nil
	case "exec.args_options":
		return ev.FieldHandlers.ResolveProcessArgsOptions(ev, ev.Exec.Process), nil
	case "exec.args_truncated":
		return ev.FieldHandlers.ResolveProcessArgsTruncated(ev, ev.Exec.Process), nil
	case "exec.argv":
		return ev.FieldHandlers.ResolveProcessArgv(ev, ev.Exec.Process), nil
	case "exec.argv0":
		return ev.FieldHandlers.ResolveProcessArgv0(ev, ev.Exec.Process), nil
	case "exec.cap_effective":
		return int(ev.Exec.Process.Credentials.CapEffective), nil
	case "exec.cap_permitted":
		return int(ev.Exec.Process.Credentials.CapPermitted), nil
	case "exec.comm":
		return ev.Exec.Process.Comm, nil
	case "exec.container.id":
		return ev.Exec.Process.ContainerID, nil
	case "exec.cookie":
		return int(ev.Exec.Process.Cookie), nil
	case "exec.created_at":
		return int(ev.FieldHandlers.ResolveProcessCreatedAt(ev, ev.Exec.Process)), nil
	case "exec.egid":
		return int(ev.Exec.Process.Credentials.EGID), nil
	case "exec.egroup":
		return ev.Exec.Process.Credentials.EGroup, nil
	case "exec.envp":
		return ev.FieldHandlers.ResolveProcessEnvp(ev, ev.Exec.Process), nil
	case "exec.envs":
		return ev.FieldHandlers.ResolveProcessEnvs(ev, ev.Exec.Process), nil
	case "exec.envs_truncated":
		return ev.FieldHandlers.ResolveProcessEnvsTruncated(ev, ev.Exec.Process), nil
	case "exec.euid":
		return int(ev.Exec.Process.Credentials.EUID), nil
	case "exec.euser":
		return ev.Exec.Process.Credentials.EUser, nil
	case "exec.file.change_time":
		return int(ev.Exec.Process.FileEvent.FileFields.CTime), nil
	case "exec.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.gid":
		return int(ev.Exec.Process.FileEvent.FileFields.GID), nil
	case "exec.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exec.Process.FileEvent.FileFields), nil
	case "exec.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exec.Process.FileEvent.FileFields), nil
	case "exec.file.inode":
		return int(ev.Exec.Process.FileEvent.FileFields.PathKey.Inode), nil
	case "exec.file.mode":
		return int(ev.Exec.Process.FileEvent.FileFields.Mode), nil
	case "exec.file.modification_time":
		return int(ev.Exec.Process.FileEvent.FileFields.MTime), nil
	case "exec.file.mount_id":
		return int(ev.Exec.Process.FileEvent.FileFields.PathKey.MountID), nil
	case "exec.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exec.Process.FileEvent.FileFields)), nil
	case "exec.file.uid":
		return int(ev.Exec.Process.FileEvent.FileFields.UID), nil
	case "exec.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exec.Process.FileEvent.FileFields), nil
	case "exec.fsgid":
		return int(ev.Exec.Process.Credentials.FSGID), nil
	case "exec.fsgroup":
		return ev.Exec.Process.Credentials.FSGroup, nil
	case "exec.fsuid":
		return int(ev.Exec.Process.Credentials.FSUID), nil
	case "exec.fsuser":
		return ev.Exec.Process.Credentials.FSUser, nil
	case "exec.gid":
		return int(ev.Exec.Process.Credentials.GID), nil
	case "exec.group":
		return ev.Exec.Process.Credentials.Group, nil
	case "exec.interpreter.file.change_time":
		return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.CTime), nil
	case "exec.interpreter.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.gid":
		return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.GID), nil
	case "exec.interpreter.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields), nil
	case "exec.interpreter.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields), nil
	case "exec.interpreter.file.inode":
		return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode), nil
	case "exec.interpreter.file.mode":
		return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.Mode), nil
	case "exec.interpreter.file.modification_time":
		return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.MTime), nil
	case "exec.interpreter.file.mount_id":
		return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID), nil
	case "exec.interpreter.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields)), nil
	case "exec.interpreter.file.uid":
		return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.UID), nil
	case "exec.interpreter.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields), nil
	case "exec.is_kworker":
		return ev.Exec.Process.PIDContext.IsKworker, nil
	case "exec.is_thread":
		return ev.Exec.Process.IsThread, nil
	case "exec.pid":
		return int(ev.Exec.Process.PIDContext.Pid), nil
	case "exec.ppid":
		return int(ev.Exec.Process.PPid), nil
	case "exec.tid":
		return int(ev.Exec.Process.PIDContext.Tid), nil
	case "exec.tty_name":
		return ev.Exec.Process.TTYName, nil
	case "exec.uid":
		return int(ev.Exec.Process.Credentials.UID), nil
	case "exec.user":
		return ev.Exec.Process.Credentials.User, nil
	case "exit.args":
		return ev.FieldHandlers.ResolveProcessArgs(ev, ev.Exit.Process), nil
	case "exit.args_flags":
		return ev.FieldHandlers.ResolveProcessArgsFlags(ev, ev.Exit.Process), nil
	case "exit.args_options":
		return ev.FieldHandlers.ResolveProcessArgsOptions(ev, ev.Exit.Process), nil
	case "exit.args_truncated":
		return ev.FieldHandlers.ResolveProcessArgsTruncated(ev, ev.Exit.Process), nil
	case "exit.argv":
		return ev.FieldHandlers.ResolveProcessArgv(ev, ev.Exit.Process), nil
	case "exit.argv0":
		return ev.FieldHandlers.ResolveProcessArgv0(ev, ev.Exit.Process), nil
	case "exit.cap_effective":
		return int(ev.Exit.Process.Credentials.CapEffective), nil
	case "exit.cap_permitted":
		return int(ev.Exit.Process.Credentials.CapPermitted), nil
	case "exit.cause":
		return int(ev.Exit.Cause), nil
	case "exit.code":
		return int(ev.Exit.Code), nil
	case "exit.comm":
		return ev.Exit.Process.Comm, nil
	case "exit.container.id":
		return ev.Exit.Process.ContainerID, nil
	case "exit.cookie":
		return int(ev.Exit.Process.Cookie), nil
	case "exit.created_at":
		return int(ev.FieldHandlers.ResolveProcessCreatedAt(ev, ev.Exit.Process)), nil
	case "exit.egid":
		return int(ev.Exit.Process.Credentials.EGID), nil
	case "exit.egroup":
		return ev.Exit.Process.Credentials.EGroup, nil
	case "exit.envp":
		return ev.FieldHandlers.ResolveProcessEnvp(ev, ev.Exit.Process), nil
	case "exit.envs":
		return ev.FieldHandlers.ResolveProcessEnvs(ev, ev.Exit.Process), nil
	case "exit.envs_truncated":
		return ev.FieldHandlers.ResolveProcessEnvsTruncated(ev, ev.Exit.Process), nil
	case "exit.euid":
		return int(ev.Exit.Process.Credentials.EUID), nil
	case "exit.euser":
		return ev.Exit.Process.Credentials.EUser, nil
	case "exit.file.change_time":
		return int(ev.Exit.Process.FileEvent.FileFields.CTime), nil
	case "exit.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.gid":
		return int(ev.Exit.Process.FileEvent.FileFields.GID), nil
	case "exit.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exit.Process.FileEvent.FileFields), nil
	case "exit.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exit.Process.FileEvent.FileFields), nil
	case "exit.file.inode":
		return int(ev.Exit.Process.FileEvent.FileFields.PathKey.Inode), nil
	case "exit.file.mode":
		return int(ev.Exit.Process.FileEvent.FileFields.Mode), nil
	case "exit.file.modification_time":
		return int(ev.Exit.Process.FileEvent.FileFields.MTime), nil
	case "exit.file.mount_id":
		return int(ev.Exit.Process.FileEvent.FileFields.PathKey.MountID), nil
	case "exit.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exit.Process.FileEvent.FileFields)), nil
	case "exit.file.uid":
		return int(ev.Exit.Process.FileEvent.FileFields.UID), nil
	case "exit.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exit.Process.FileEvent.FileFields), nil
	case "exit.fsgid":
		return int(ev.Exit.Process.Credentials.FSGID), nil
	case "exit.fsgroup":
		return ev.Exit.Process.Credentials.FSGroup, nil
	case "exit.fsuid":
		return int(ev.Exit.Process.Credentials.FSUID), nil
	case "exit.fsuser":
		return ev.Exit.Process.Credentials.FSUser, nil
	case "exit.gid":
		return int(ev.Exit.Process.Credentials.GID), nil
	case "exit.group":
		return ev.Exit.Process.Credentials.Group, nil
	case "exit.interpreter.file.change_time":
		return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.CTime), nil
	case "exit.interpreter.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.gid":
		return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.GID), nil
	case "exit.interpreter.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields), nil
	case "exit.interpreter.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields), nil
	case "exit.interpreter.file.inode":
		return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode), nil
	case "exit.interpreter.file.mode":
		return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.Mode), nil
	case "exit.interpreter.file.modification_time":
		return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.MTime), nil
	case "exit.interpreter.file.mount_id":
		return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID), nil
	case "exit.interpreter.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields)), nil
	case "exit.interpreter.file.uid":
		return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.UID), nil
	case "exit.interpreter.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields), nil
	case "exit.is_kworker":
		return ev.Exit.Process.PIDContext.IsKworker, nil
	case "exit.is_thread":
		return ev.Exit.Process.IsThread, nil
	case "exit.pid":
		return int(ev.Exit.Process.PIDContext.Pid), nil
	case "exit.ppid":
		return int(ev.Exit.Process.PPid), nil
	case "exit.tid":
		return int(ev.Exit.Process.PIDContext.Tid), nil
	case "exit.tty_name":
		return ev.Exit.Process.TTYName, nil
	case "exit.uid":
		return int(ev.Exit.Process.Credentials.UID), nil
	case "exit.user":
		return ev.Exit.Process.Credentials.User, nil
	}
	return nil, &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) GetFieldEventType(field eval.Field) (eval.EventType, error) {
	switch field {
	case "exec.args":
		return "exec", nil
	case "exec.args_flags":
		return "exec", nil
	case "exec.args_options":
		return "exec", nil
	case "exec.args_truncated":
		return "exec", nil
	case "exec.argv":
		return "exec", nil
	case "exec.argv0":
		return "exec", nil
	case "exec.cap_effective":
		return "exec", nil
	case "exec.cap_permitted":
		return "exec", nil
	case "exec.comm":
		return "exec", nil
	case "exec.container.id":
		return "exec", nil
	case "exec.cookie":
		return "exec", nil
	case "exec.created_at":
		return "exec", nil
	case "exec.egid":
		return "exec", nil
	case "exec.egroup":
		return "exec", nil
	case "exec.envp":
		return "exec", nil
	case "exec.envs":
		return "exec", nil
	case "exec.envs_truncated":
		return "exec", nil
	case "exec.euid":
		return "exec", nil
	case "exec.euser":
		return "exec", nil
	case "exec.file.change_time":
		return "exec", nil
	case "exec.file.filesystem":
		return "exec", nil
	case "exec.file.gid":
		return "exec", nil
	case "exec.file.group":
		return "exec", nil
	case "exec.file.in_upper_layer":
		return "exec", nil
	case "exec.file.inode":
		return "exec", nil
	case "exec.file.mode":
		return "exec", nil
	case "exec.file.modification_time":
		return "exec", nil
	case "exec.file.mount_id":
		return "exec", nil
	case "exec.file.name":
		return "exec", nil
	case "exec.file.name.length":
		return "exec", nil
	case "exec.file.package.name":
		return "exec", nil
	case "exec.file.package.source_version":
		return "exec", nil
	case "exec.file.package.version":
		return "exec", nil
	case "exec.file.path":
		return "exec", nil
	case "exec.file.path.length":
		return "exec", nil
	case "exec.file.rights":
		return "exec", nil
	case "exec.file.uid":
		return "exec", nil
	case "exec.file.user":
		return "exec", nil
	case "exec.fsgid":
		return "exec", nil
	case "exec.fsgroup":
		return "exec", nil
	case "exec.fsuid":
		return "exec", nil
	case "exec.fsuser":
		return "exec", nil
	case "exec.gid":
		return "exec", nil
	case "exec.group":
		return "exec", nil
	case "exec.interpreter.file.change_time":
		return "exec", nil
	case "exec.interpreter.file.filesystem":
		return "exec", nil
	case "exec.interpreter.file.gid":
		return "exec", nil
	case "exec.interpreter.file.group":
		return "exec", nil
	case "exec.interpreter.file.in_upper_layer":
		return "exec", nil
	case "exec.interpreter.file.inode":
		return "exec", nil
	case "exec.interpreter.file.mode":
		return "exec", nil
	case "exec.interpreter.file.modification_time":
		return "exec", nil
	case "exec.interpreter.file.mount_id":
		return "exec", nil
	case "exec.interpreter.file.name":
		return "exec", nil
	case "exec.interpreter.file.name.length":
		return "exec", nil
	case "exec.interpreter.file.package.name":
		return "exec", nil
	case "exec.interpreter.file.package.source_version":
		return "exec", nil
	case "exec.interpreter.file.package.version":
		return "exec", nil
	case "exec.interpreter.file.path":
		return "exec", nil
	case "exec.interpreter.file.path.length":
		return "exec", nil
	case "exec.interpreter.file.rights":
		return "exec", nil
	case "exec.interpreter.file.uid":
		return "exec", nil
	case "exec.interpreter.file.user":
		return "exec", nil
	case "exec.is_kworker":
		return "exec", nil
	case "exec.is_thread":
		return "exec", nil
	case "exec.pid":
		return "exec", nil
	case "exec.ppid":
		return "exec", nil
	case "exec.tid":
		return "exec", nil
	case "exec.tty_name":
		return "exec", nil
	case "exec.uid":
		return "exec", nil
	case "exec.user":
		return "exec", nil
	case "exit.args":
		return "exit", nil
	case "exit.args_flags":
		return "exit", nil
	case "exit.args_options":
		return "exit", nil
	case "exit.args_truncated":
		return "exit", nil
	case "exit.argv":
		return "exit", nil
	case "exit.argv0":
		return "exit", nil
	case "exit.cap_effective":
		return "exit", nil
	case "exit.cap_permitted":
		return "exit", nil
	case "exit.cause":
		return "exit", nil
	case "exit.code":
		return "exit", nil
	case "exit.comm":
		return "exit", nil
	case "exit.container.id":
		return "exit", nil
	case "exit.cookie":
		return "exit", nil
	case "exit.created_at":
		return "exit", nil
	case "exit.egid":
		return "exit", nil
	case "exit.egroup":
		return "exit", nil
	case "exit.envp":
		return "exit", nil
	case "exit.envs":
		return "exit", nil
	case "exit.envs_truncated":
		return "exit", nil
	case "exit.euid":
		return "exit", nil
	case "exit.euser":
		return "exit", nil
	case "exit.file.change_time":
		return "exit", nil
	case "exit.file.filesystem":
		return "exit", nil
	case "exit.file.gid":
		return "exit", nil
	case "exit.file.group":
		return "exit", nil
	case "exit.file.in_upper_layer":
		return "exit", nil
	case "exit.file.inode":
		return "exit", nil
	case "exit.file.mode":
		return "exit", nil
	case "exit.file.modification_time":
		return "exit", nil
	case "exit.file.mount_id":
		return "exit", nil
	case "exit.file.name":
		return "exit", nil
	case "exit.file.name.length":
		return "exit", nil
	case "exit.file.package.name":
		return "exit", nil
	case "exit.file.package.source_version":
		return "exit", nil
	case "exit.file.package.version":
		return "exit", nil
	case "exit.file.path":
		return "exit", nil
	case "exit.file.path.length":
		return "exit", nil
	case "exit.file.rights":
		return "exit", nil
	case "exit.file.uid":
		return "exit", nil
	case "exit.file.user":
		return "exit", nil
	case "exit.fsgid":
		return "exit", nil
	case "exit.fsgroup":
		return "exit", nil
	case "exit.fsuid":
		return "exit", nil
	case "exit.fsuser":
		return "exit", nil
	case "exit.gid":
		return "exit", nil
	case "exit.group":
		return "exit", nil
	case "exit.interpreter.file.change_time":
		return "exit", nil
	case "exit.interpreter.file.filesystem":
		return "exit", nil
	case "exit.interpreter.file.gid":
		return "exit", nil
	case "exit.interpreter.file.group":
		return "exit", nil
	case "exit.interpreter.file.in_upper_layer":
		return "exit", nil
	case "exit.interpreter.file.inode":
		return "exit", nil
	case "exit.interpreter.file.mode":
		return "exit", nil
	case "exit.interpreter.file.modification_time":
		return "exit", nil
	case "exit.interpreter.file.mount_id":
		return "exit", nil
	case "exit.interpreter.file.name":
		return "exit", nil
	case "exit.interpreter.file.name.length":
		return "exit", nil
	case "exit.interpreter.file.package.name":
		return "exit", nil
	case "exit.interpreter.file.package.source_version":
		return "exit", nil
	case "exit.interpreter.file.package.version":
		return "exit", nil
	case "exit.interpreter.file.path":
		return "exit", nil
	case "exit.interpreter.file.path.length":
		return "exit", nil
	case "exit.interpreter.file.rights":
		return "exit", nil
	case "exit.interpreter.file.uid":
		return "exit", nil
	case "exit.interpreter.file.user":
		return "exit", nil
	case "exit.is_kworker":
		return "exit", nil
	case "exit.is_thread":
		return "exit", nil
	case "exit.pid":
		return "exit", nil
	case "exit.ppid":
		return "exit", nil
	case "exit.tid":
		return "exit", nil
	case "exit.tty_name":
		return "exit", nil
	case "exit.uid":
		return "exit", nil
	case "exit.user":
		return "exit", nil
	}
	return "", &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) GetFieldType(field eval.Field) (reflect.Kind, error) {
	switch field {
	case "exec.args":
		return reflect.String, nil
	case "exec.args_flags":
		return reflect.String, nil
	case "exec.args_options":
		return reflect.String, nil
	case "exec.args_truncated":
		return reflect.Bool, nil
	case "exec.argv":
		return reflect.String, nil
	case "exec.argv0":
		return reflect.String, nil
	case "exec.cap_effective":
		return reflect.Int, nil
	case "exec.cap_permitted":
		return reflect.Int, nil
	case "exec.comm":
		return reflect.String, nil
	case "exec.container.id":
		return reflect.String, nil
	case "exec.cookie":
		return reflect.Int, nil
	case "exec.created_at":
		return reflect.Int, nil
	case "exec.egid":
		return reflect.Int, nil
	case "exec.egroup":
		return reflect.String, nil
	case "exec.envp":
		return reflect.String, nil
	case "exec.envs":
		return reflect.String, nil
	case "exec.envs_truncated":
		return reflect.Bool, nil
	case "exec.euid":
		return reflect.Int, nil
	case "exec.euser":
		return reflect.String, nil
	case "exec.file.change_time":
		return reflect.Int, nil
	case "exec.file.filesystem":
		return reflect.String, nil
	case "exec.file.gid":
		return reflect.Int, nil
	case "exec.file.group":
		return reflect.String, nil
	case "exec.file.in_upper_layer":
		return reflect.Bool, nil
	case "exec.file.inode":
		return reflect.Int, nil
	case "exec.file.mode":
		return reflect.Int, nil
	case "exec.file.modification_time":
		return reflect.Int, nil
	case "exec.file.mount_id":
		return reflect.Int, nil
	case "exec.file.name":
		return reflect.String, nil
	case "exec.file.name.length":
		return reflect.Int, nil
	case "exec.file.package.name":
		return reflect.String, nil
	case "exec.file.package.source_version":
		return reflect.String, nil
	case "exec.file.package.version":
		return reflect.String, nil
	case "exec.file.path":
		return reflect.String, nil
	case "exec.file.path.length":
		return reflect.Int, nil
	case "exec.file.rights":
		return reflect.Int, nil
	case "exec.file.uid":
		return reflect.Int, nil
	case "exec.file.user":
		return reflect.String, nil
	case "exec.fsgid":
		return reflect.Int, nil
	case "exec.fsgroup":
		return reflect.String, nil
	case "exec.fsuid":
		return reflect.Int, nil
	case "exec.fsuser":
		return reflect.String, nil
	case "exec.gid":
		return reflect.Int, nil
	case "exec.group":
		return reflect.String, nil
	case "exec.interpreter.file.change_time":
		return reflect.Int, nil
	case "exec.interpreter.file.filesystem":
		return reflect.String, nil
	case "exec.interpreter.file.gid":
		return reflect.Int, nil
	case "exec.interpreter.file.group":
		return reflect.String, nil
	case "exec.interpreter.file.in_upper_layer":
		return reflect.Bool, nil
	case "exec.interpreter.file.inode":
		return reflect.Int, nil
	case "exec.interpreter.file.mode":
		return reflect.Int, nil
	case "exec.interpreter.file.modification_time":
		return reflect.Int, nil
	case "exec.interpreter.file.mount_id":
		return reflect.Int, nil
	case "exec.interpreter.file.name":
		return reflect.String, nil
	case "exec.interpreter.file.name.length":
		return reflect.Int, nil
	case "exec.interpreter.file.package.name":
		return reflect.String, nil
	case "exec.interpreter.file.package.source_version":
		return reflect.String, nil
	case "exec.interpreter.file.package.version":
		return reflect.String, nil
	case "exec.interpreter.file.path":
		return reflect.String, nil
	case "exec.interpreter.file.path.length":
		return reflect.Int, nil
	case "exec.interpreter.file.rights":
		return reflect.Int, nil
	case "exec.interpreter.file.uid":
		return reflect.Int, nil
	case "exec.interpreter.file.user":
		return reflect.String, nil
	case "exec.is_kworker":
		return reflect.Bool, nil
	case "exec.is_thread":
		return reflect.Bool, nil
	case "exec.pid":
		return reflect.Int, nil
	case "exec.ppid":
		return reflect.Int, nil
	case "exec.tid":
		return reflect.Int, nil
	case "exec.tty_name":
		return reflect.String, nil
	case "exec.uid":
		return reflect.Int, nil
	case "exec.user":
		return reflect.String, nil
	case "exit.args":
		return reflect.String, nil
	case "exit.args_flags":
		return reflect.String, nil
	case "exit.args_options":
		return reflect.String, nil
	case "exit.args_truncated":
		return reflect.Bool, nil
	case "exit.argv":
		return reflect.String, nil
	case "exit.argv0":
		return reflect.String, nil
	case "exit.cap_effective":
		return reflect.Int, nil
	case "exit.cap_permitted":
		return reflect.Int, nil
	case "exit.cause":
		return reflect.Int, nil
	case "exit.code":
		return reflect.Int, nil
	case "exit.comm":
		return reflect.String, nil
	case "exit.container.id":
		return reflect.String, nil
	case "exit.cookie":
		return reflect.Int, nil
	case "exit.created_at":
		return reflect.Int, nil
	case "exit.egid":
		return reflect.Int, nil
	case "exit.egroup":
		return reflect.String, nil
	case "exit.envp":
		return reflect.String, nil
	case "exit.envs":
		return reflect.String, nil
	case "exit.envs_truncated":
		return reflect.Bool, nil
	case "exit.euid":
		return reflect.Int, nil
	case "exit.euser":
		return reflect.String, nil
	case "exit.file.change_time":
		return reflect.Int, nil
	case "exit.file.filesystem":
		return reflect.String, nil
	case "exit.file.gid":
		return reflect.Int, nil
	case "exit.file.group":
		return reflect.String, nil
	case "exit.file.in_upper_layer":
		return reflect.Bool, nil
	case "exit.file.inode":
		return reflect.Int, nil
	case "exit.file.mode":
		return reflect.Int, nil
	case "exit.file.modification_time":
		return reflect.Int, nil
	case "exit.file.mount_id":
		return reflect.Int, nil
	case "exit.file.name":
		return reflect.String, nil
	case "exit.file.name.length":
		return reflect.Int, nil
	case "exit.file.package.name":
		return reflect.String, nil
	case "exit.file.package.source_version":
		return reflect.String, nil
	case "exit.file.package.version":
		return reflect.String, nil
	case "exit.file.path":
		return reflect.String, nil
	case "exit.file.path.length":
		return reflect.Int, nil
	case "exit.file.rights":
		return reflect.Int, nil
	case "exit.file.uid":
		return reflect.Int, nil
	case "exit.file.user":
		return reflect.String, nil
	case "exit.fsgid":
		return reflect.Int, nil
	case "exit.fsgroup":
		return reflect.String, nil
	case "exit.fsuid":
		return reflect.Int, nil
	case "exit.fsuser":
		return reflect.String, nil
	case "exit.gid":
		return reflect.Int, nil
	case "exit.group":
		return reflect.String, nil
	case "exit.interpreter.file.change_time":
		return reflect.Int, nil
	case "exit.interpreter.file.filesystem":
		return reflect.String, nil
	case "exit.interpreter.file.gid":
		return reflect.Int, nil
	case "exit.interpreter.file.group":
		return reflect.String, nil
	case "exit.interpreter.file.in_upper_layer":
		return reflect.Bool, nil
	case "exit.interpreter.file.inode":
		return reflect.Int, nil
	case "exit.interpreter.file.mode":
		return reflect.Int, nil
	case "exit.interpreter.file.modification_time":
		return reflect.Int, nil
	case "exit.interpreter.file.mount_id":
		return reflect.Int, nil
	case "exit.interpreter.file.name":
		return reflect.String, nil
	case "exit.interpreter.file.name.length":
		return reflect.Int, nil
	case "exit.interpreter.file.package.name":
		return reflect.String, nil
	case "exit.interpreter.file.package.source_version":
		return reflect.String, nil
	case "exit.interpreter.file.package.version":
		return reflect.String, nil
	case "exit.interpreter.file.path":
		return reflect.String, nil
	case "exit.interpreter.file.path.length":
		return reflect.Int, nil
	case "exit.interpreter.file.rights":
		return reflect.Int, nil
	case "exit.interpreter.file.uid":
		return reflect.Int, nil
	case "exit.interpreter.file.user":
		return reflect.String, nil
	case "exit.is_kworker":
		return reflect.Bool, nil
	case "exit.is_thread":
		return reflect.Bool, nil
	case "exit.pid":
		return reflect.Int, nil
	case "exit.ppid":
		return reflect.Int, nil
	case "exit.tid":
		return reflect.Int, nil
	case "exit.tty_name":
		return reflect.String, nil
	case "exit.uid":
		return reflect.Int, nil
	case "exit.user":
		return reflect.String, nil
	}
	return reflect.Invalid, &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) SetFieldValue(field eval.Field, value interface{}) error {
	switch field {
	case "exec.args":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Args"}
		}
		ev.Exec.Process.Args = rv
		return nil
	case "exec.args_flags":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exec.Process.Argv = append(ev.Exec.Process.Argv, rv)
		case []string:
			ev.Exec.Process.Argv = append(ev.Exec.Process.Argv, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Argv"}
		}
		return nil
	case "exec.args_options":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exec.Process.Argv = append(ev.Exec.Process.Argv, rv)
		case []string:
			ev.Exec.Process.Argv = append(ev.Exec.Process.Argv, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Argv"}
		}
		return nil
	case "exec.args_truncated":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.ArgsTruncated"}
		}
		ev.Exec.Process.ArgsTruncated = rv
		return nil
	case "exec.argv":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exec.Process.Argv = append(ev.Exec.Process.Argv, rv)
		case []string:
			ev.Exec.Process.Argv = append(ev.Exec.Process.Argv, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Argv"}
		}
		return nil
	case "exec.argv0":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Argv0"}
		}
		ev.Exec.Process.Argv0 = rv
		return nil
	case "exec.cap_effective":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.CapEffective"}
		}
		ev.Exec.Process.Credentials.CapEffective = uint64(rv)
		return nil
	case "exec.cap_permitted":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.CapPermitted"}
		}
		ev.Exec.Process.Credentials.CapPermitted = uint64(rv)
		return nil
	case "exec.comm":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Comm"}
		}
		ev.Exec.Process.Comm = rv
		return nil
	case "exec.container.id":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.ContainerID"}
		}
		ev.Exec.Process.ContainerID = rv
		return nil
	case "exec.cookie":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Cookie"}
		}
		ev.Exec.Process.Cookie = uint32(rv)
		return nil
	case "exec.created_at":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.CreatedAt"}
		}
		ev.Exec.Process.CreatedAt = uint64(rv)
		return nil
	case "exec.egid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.EGID"}
		}
		ev.Exec.Process.Credentials.EGID = uint32(rv)
		return nil
	case "exec.egroup":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.EGroup"}
		}
		ev.Exec.Process.Credentials.EGroup = rv
		return nil
	case "exec.envp":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exec.Process.Envp = append(ev.Exec.Process.Envp, rv)
		case []string:
			ev.Exec.Process.Envp = append(ev.Exec.Process.Envp, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Envp"}
		}
		return nil
	case "exec.envs":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exec.Process.Envs = append(ev.Exec.Process.Envs, rv)
		case []string:
			ev.Exec.Process.Envs = append(ev.Exec.Process.Envs, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Envs"}
		}
		return nil
	case "exec.envs_truncated":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.EnvsTruncated"}
		}
		ev.Exec.Process.EnvsTruncated = rv
		return nil
	case "exec.euid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.EUID"}
		}
		ev.Exec.Process.Credentials.EUID = uint32(rv)
		return nil
	case "exec.euser":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.EUser"}
		}
		ev.Exec.Process.Credentials.EUser = rv
		return nil
	case "exec.file.change_time":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.CTime"}
		}
		ev.Exec.Process.FileEvent.FileFields.CTime = uint64(rv)
		return nil
	case "exec.file.filesystem":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.Filesystem"}
		}
		ev.Exec.Process.FileEvent.Filesystem = rv
		return nil
	case "exec.file.gid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.GID"}
		}
		ev.Exec.Process.FileEvent.FileFields.GID = uint32(rv)
		return nil
	case "exec.file.group":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.Group"}
		}
		ev.Exec.Process.FileEvent.FileFields.Group = rv
		return nil
	case "exec.file.in_upper_layer":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.InUpperLayer"}
		}
		ev.Exec.Process.FileEvent.FileFields.InUpperLayer = rv
		return nil
	case "exec.file.inode":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.PathKey.Inode"}
		}
		ev.Exec.Process.FileEvent.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "exec.file.mode":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.Mode"}
		}
		ev.Exec.Process.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exec.file.modification_time":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.MTime"}
		}
		ev.Exec.Process.FileEvent.FileFields.MTime = uint64(rv)
		return nil
	case "exec.file.mount_id":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.PathKey.MountID"}
		}
		ev.Exec.Process.FileEvent.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "exec.file.name":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.BasenameStr"}
		}
		ev.Exec.Process.FileEvent.BasenameStr = rv
		return nil
	case "exec.file.name.length":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exec.file.name.length"}
	case "exec.file.package.name":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.PkgName"}
		}
		ev.Exec.Process.FileEvent.PkgName = rv
		return nil
	case "exec.file.package.source_version":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.PkgSrcVersion"}
		}
		ev.Exec.Process.FileEvent.PkgSrcVersion = rv
		return nil
	case "exec.file.package.version":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.PkgVersion"}
		}
		ev.Exec.Process.FileEvent.PkgVersion = rv
		return nil
	case "exec.file.path":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.PathnameStr"}
		}
		ev.Exec.Process.FileEvent.PathnameStr = rv
		return nil
	case "exec.file.path.length":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exec.file.path.length"}
	case "exec.file.rights":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.Mode"}
		}
		ev.Exec.Process.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exec.file.uid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.UID"}
		}
		ev.Exec.Process.FileEvent.FileFields.UID = uint32(rv)
		return nil
	case "exec.file.user":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.User"}
		}
		ev.Exec.Process.FileEvent.FileFields.User = rv
		return nil
	case "exec.fsgid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.FSGID"}
		}
		ev.Exec.Process.Credentials.FSGID = uint32(rv)
		return nil
	case "exec.fsgroup":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.FSGroup"}
		}
		ev.Exec.Process.Credentials.FSGroup = rv
		return nil
	case "exec.fsuid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.FSUID"}
		}
		ev.Exec.Process.Credentials.FSUID = uint32(rv)
		return nil
	case "exec.fsuser":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.FSUser"}
		}
		ev.Exec.Process.Credentials.FSUser = rv
		return nil
	case "exec.gid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.GID"}
		}
		ev.Exec.Process.Credentials.GID = uint32(rv)
		return nil
	case "exec.group":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.Group"}
		}
		ev.Exec.Process.Credentials.Group = rv
		return nil
	case "exec.interpreter.file.change_time":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.CTime"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.CTime = uint64(rv)
		return nil
	case "exec.interpreter.file.filesystem":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.Filesystem"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.Filesystem = rv
		return nil
	case "exec.interpreter.file.gid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.GID"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.GID = uint32(rv)
		return nil
	case "exec.interpreter.file.group":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.Group"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.Group = rv
		return nil
	case "exec.interpreter.file.in_upper_layer":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.InUpperLayer"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.InUpperLayer = rv
		return nil
	case "exec.interpreter.file.inode":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "exec.interpreter.file.mode":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.Mode"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exec.interpreter.file.modification_time":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.MTime"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.MTime = uint64(rv)
		return nil
	case "exec.interpreter.file.mount_id":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "exec.interpreter.file.name":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.BasenameStr"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.BasenameStr = rv
		return nil
	case "exec.interpreter.file.name.length":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exec.interpreter.file.name.length"}
	case "exec.interpreter.file.package.name":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.PkgName"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.PkgName = rv
		return nil
	case "exec.interpreter.file.package.source_version":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.PkgSrcVersion"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.PkgSrcVersion = rv
		return nil
	case "exec.interpreter.file.package.version":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.PkgVersion"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.PkgVersion = rv
		return nil
	case "exec.interpreter.file.path":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.PathnameStr"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.PathnameStr = rv
		return nil
	case "exec.interpreter.file.path.length":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exec.interpreter.file.path.length"}
	case "exec.interpreter.file.rights":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.Mode"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exec.interpreter.file.uid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.UID"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.UID = uint32(rv)
		return nil
	case "exec.interpreter.file.user":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.User"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.User = rv
		return nil
	case "exec.is_kworker":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.PIDContext.IsKworker"}
		}
		ev.Exec.Process.PIDContext.IsKworker = rv
		return nil
	case "exec.is_thread":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.IsThread"}
		}
		ev.Exec.Process.IsThread = rv
		return nil
	case "exec.pid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.PIDContext.Pid"}
		}
		ev.Exec.Process.PIDContext.Pid = uint32(rv)
		return nil
	case "exec.ppid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.PPid"}
		}
		ev.Exec.Process.PPid = uint32(rv)
		return nil
	case "exec.tid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.PIDContext.Tid"}
		}
		ev.Exec.Process.PIDContext.Tid = uint32(rv)
		return nil
	case "exec.tty_name":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.TTYName"}
		}
		ev.Exec.Process.TTYName = rv
		return nil
	case "exec.uid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.UID"}
		}
		ev.Exec.Process.Credentials.UID = uint32(rv)
		return nil
	case "exec.user":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.User"}
		}
		ev.Exec.Process.Credentials.User = rv
		return nil
	case "exit.args":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Args"}
		}
		ev.Exit.Process.Args = rv
		return nil
	case "exit.args_flags":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exit.Process.Argv = append(ev.Exit.Process.Argv, rv)
		case []string:
			ev.Exit.Process.Argv = append(ev.Exit.Process.Argv, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Argv"}
		}
		return nil
	case "exit.args_options":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exit.Process.Argv = append(ev.Exit.Process.Argv, rv)
		case []string:
			ev.Exit.Process.Argv = append(ev.Exit.Process.Argv, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Argv"}
		}
		return nil
	case "exit.args_truncated":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.ArgsTruncated"}
		}
		ev.Exit.Process.ArgsTruncated = rv
		return nil
	case "exit.argv":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exit.Process.Argv = append(ev.Exit.Process.Argv, rv)
		case []string:
			ev.Exit.Process.Argv = append(ev.Exit.Process.Argv, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Argv"}
		}
		return nil
	case "exit.argv0":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Argv0"}
		}
		ev.Exit.Process.Argv0 = rv
		return nil
	case "exit.cap_effective":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.CapEffective"}
		}
		ev.Exit.Process.Credentials.CapEffective = uint64(rv)
		return nil
	case "exit.cap_permitted":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.CapPermitted"}
		}
		ev.Exit.Process.Credentials.CapPermitted = uint64(rv)
		return nil
	case "exit.cause":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Cause"}
		}
		ev.Exit.Cause = uint32(rv)
		return nil
	case "exit.code":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Code"}
		}
		ev.Exit.Code = uint32(rv)
		return nil
	case "exit.comm":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Comm"}
		}
		ev.Exit.Process.Comm = rv
		return nil
	case "exit.container.id":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.ContainerID"}
		}
		ev.Exit.Process.ContainerID = rv
		return nil
	case "exit.cookie":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Cookie"}
		}
		ev.Exit.Process.Cookie = uint32(rv)
		return nil
	case "exit.created_at":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.CreatedAt"}
		}
		ev.Exit.Process.CreatedAt = uint64(rv)
		return nil
	case "exit.egid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.EGID"}
		}
		ev.Exit.Process.Credentials.EGID = uint32(rv)
		return nil
	case "exit.egroup":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.EGroup"}
		}
		ev.Exit.Process.Credentials.EGroup = rv
		return nil
	case "exit.envp":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exit.Process.Envp = append(ev.Exit.Process.Envp, rv)
		case []string:
			ev.Exit.Process.Envp = append(ev.Exit.Process.Envp, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Envp"}
		}
		return nil
	case "exit.envs":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exit.Process.Envs = append(ev.Exit.Process.Envs, rv)
		case []string:
			ev.Exit.Process.Envs = append(ev.Exit.Process.Envs, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Envs"}
		}
		return nil
	case "exit.envs_truncated":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.EnvsTruncated"}
		}
		ev.Exit.Process.EnvsTruncated = rv
		return nil
	case "exit.euid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.EUID"}
		}
		ev.Exit.Process.Credentials.EUID = uint32(rv)
		return nil
	case "exit.euser":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.EUser"}
		}
		ev.Exit.Process.Credentials.EUser = rv
		return nil
	case "exit.file.change_time":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.CTime"}
		}
		ev.Exit.Process.FileEvent.FileFields.CTime = uint64(rv)
		return nil
	case "exit.file.filesystem":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.Filesystem"}
		}
		ev.Exit.Process.FileEvent.Filesystem = rv
		return nil
	case "exit.file.gid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.GID"}
		}
		ev.Exit.Process.FileEvent.FileFields.GID = uint32(rv)
		return nil
	case "exit.file.group":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.Group"}
		}
		ev.Exit.Process.FileEvent.FileFields.Group = rv
		return nil
	case "exit.file.in_upper_layer":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.InUpperLayer"}
		}
		ev.Exit.Process.FileEvent.FileFields.InUpperLayer = rv
		return nil
	case "exit.file.inode":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.PathKey.Inode"}
		}
		ev.Exit.Process.FileEvent.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "exit.file.mode":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.Mode"}
		}
		ev.Exit.Process.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exit.file.modification_time":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.MTime"}
		}
		ev.Exit.Process.FileEvent.FileFields.MTime = uint64(rv)
		return nil
	case "exit.file.mount_id":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.PathKey.MountID"}
		}
		ev.Exit.Process.FileEvent.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "exit.file.name":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.BasenameStr"}
		}
		ev.Exit.Process.FileEvent.BasenameStr = rv
		return nil
	case "exit.file.name.length":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exit.file.name.length"}
	case "exit.file.package.name":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.PkgName"}
		}
		ev.Exit.Process.FileEvent.PkgName = rv
		return nil
	case "exit.file.package.source_version":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.PkgSrcVersion"}
		}
		ev.Exit.Process.FileEvent.PkgSrcVersion = rv
		return nil
	case "exit.file.package.version":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.PkgVersion"}
		}
		ev.Exit.Process.FileEvent.PkgVersion = rv
		return nil
	case "exit.file.path":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.PathnameStr"}
		}
		ev.Exit.Process.FileEvent.PathnameStr = rv
		return nil
	case "exit.file.path.length":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exit.file.path.length"}
	case "exit.file.rights":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.Mode"}
		}
		ev.Exit.Process.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exit.file.uid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.UID"}
		}
		ev.Exit.Process.FileEvent.FileFields.UID = uint32(rv)
		return nil
	case "exit.file.user":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.User"}
		}
		ev.Exit.Process.FileEvent.FileFields.User = rv
		return nil
	case "exit.fsgid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.FSGID"}
		}
		ev.Exit.Process.Credentials.FSGID = uint32(rv)
		return nil
	case "exit.fsgroup":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.FSGroup"}
		}
		ev.Exit.Process.Credentials.FSGroup = rv
		return nil
	case "exit.fsuid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.FSUID"}
		}
		ev.Exit.Process.Credentials.FSUID = uint32(rv)
		return nil
	case "exit.fsuser":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.FSUser"}
		}
		ev.Exit.Process.Credentials.FSUser = rv
		return nil
	case "exit.gid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.GID"}
		}
		ev.Exit.Process.Credentials.GID = uint32(rv)
		return nil
	case "exit.group":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.Group"}
		}
		ev.Exit.Process.Credentials.Group = rv
		return nil
	case "exit.interpreter.file.change_time":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.CTime"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.CTime = uint64(rv)
		return nil
	case "exit.interpreter.file.filesystem":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.Filesystem"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.Filesystem = rv
		return nil
	case "exit.interpreter.file.gid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.GID"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.GID = uint32(rv)
		return nil
	case "exit.interpreter.file.group":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.Group"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.Group = rv
		return nil
	case "exit.interpreter.file.in_upper_layer":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.InUpperLayer"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.InUpperLayer = rv
		return nil
	case "exit.interpreter.file.inode":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "exit.interpreter.file.mode":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.Mode"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exit.interpreter.file.modification_time":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.MTime"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.MTime = uint64(rv)
		return nil
	case "exit.interpreter.file.mount_id":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "exit.interpreter.file.name":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.BasenameStr"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.BasenameStr = rv
		return nil
	case "exit.interpreter.file.name.length":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exit.interpreter.file.name.length"}
	case "exit.interpreter.file.package.name":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.PkgName"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.PkgName = rv
		return nil
	case "exit.interpreter.file.package.source_version":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.PkgSrcVersion"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.PkgSrcVersion = rv
		return nil
	case "exit.interpreter.file.package.version":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.PkgVersion"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.PkgVersion = rv
		return nil
	case "exit.interpreter.file.path":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.PathnameStr"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.PathnameStr = rv
		return nil
	case "exit.interpreter.file.path.length":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exit.interpreter.file.path.length"}
	case "exit.interpreter.file.rights":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.Mode"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exit.interpreter.file.uid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.UID"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.UID = uint32(rv)
		return nil
	case "exit.interpreter.file.user":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.User"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.User = rv
		return nil
	case "exit.is_kworker":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.PIDContext.IsKworker"}
		}
		ev.Exit.Process.PIDContext.IsKworker = rv
		return nil
	case "exit.is_thread":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.IsThread"}
		}
		ev.Exit.Process.IsThread = rv
		return nil
	case "exit.pid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.PIDContext.Pid"}
		}
		ev.Exit.Process.PIDContext.Pid = uint32(rv)
		return nil
	case "exit.ppid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.PPid"}
		}
		ev.Exit.Process.PPid = uint32(rv)
		return nil
	case "exit.tid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.PIDContext.Tid"}
		}
		ev.Exit.Process.PIDContext.Tid = uint32(rv)
		return nil
	case "exit.tty_name":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.TTYName"}
		}
		ev.Exit.Process.TTYName = rv
		return nil
	case "exit.uid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.UID"}
		}
		ev.Exit.Process.Credentials.UID = uint32(rv)
		return nil
	case "exit.user":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.User"}
		}
		ev.Exit.Process.Credentials.User = rv
		return nil
	}
	return &eval.ErrFieldNotFound{Field: field}
}
