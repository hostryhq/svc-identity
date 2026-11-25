package service

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

// Security review M8: the approver must see what the stored request body would do, not only the
// operation and the path. approvalSummary renders it from the body that was filed, looking up the
// names of roles and members in the organisation's own data, so the approver reads "Cashier", not a
// role id. Only fields on an allow-list per operation are read: a PIN, a nonce, a signature, a public key or
// a token in a body never reaches the summary. The names a requester types (a new member's display
// name, a new role's name) are shown because the approver must see them, but they are cleaned of control
// characters and cut short; they cannot add lines or fake a second sentence.
//
// Seven approvable operations carry what they change in the body: createMember, updateMember,
// createRoleAssignment, createRole, updateRole, createActivationCode and registerDevice. Every other
// approvable operation is fully described by its path, which the subject already names.

const (
	maxName    = 60
	maxListed  = 12
	maxSubject = 500
)

// clean makes requester-typed text safe to show inside a sentence.
func clean(s string, max int) string {
	var b strings.Builder
	space := true
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			continue
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r):
			if !space {
				b.WriteByte(' ')
			}
			space = true
		default:
			b.WriteRune(r)
			space = false
		}
	}
	out := strings.TrimSpace(b.String())
	if rs := []rune(out); len(rs) > max {
		out = string(rs[:max]) + "..."
	}
	return out
}

func quoted(s string) string { return `"` + clean(s, maxName) + `"` }

func outletsText(ids []string) string {
	switch len(ids) {
	case 0:
		return "all outlets"
	case 1:
		return "1 outlet"
	}
	return fmt.Sprintf("%d outlets", len(ids))
}

func listText(items []string) string {
	sort.Strings(items)
	if len(items) > maxListed {
		return strings.Join(items[:maxListed], ", ") + fmt.Sprintf(" and %d more", len(items)-maxListed)
	}
	return strings.Join(items, ", ")
}

// pathID returns the n-th segment of a concrete path such as /v1/members/{id}/role-assignments.
func pathID(path string, n int) string {
	parts := strings.Split(path, "/")
	if n < len(parts) {
		return parts[n]
	}
	return ""
}

func (s *Service) roleName(tx repository.Tx, tenant, id string) string {
	if r, _ := get[role](tx, kRole, tenant, id); r != nil {
		return quoted(r.Name)
	}
	return "an unknown role"
}

func (s *Service) memberName(tx repository.Tx, tenant, id string) string {
	if m, _ := get[member](tx, kMember, tenant, id); m != nil {
		return quoted(m.DisplayName)
	}
	return "an unknown member"
}

func (s *Service) assignmentText(tx repository.Tx, tenant string, a gen.AssignmentInput) string {
	var outlets []string
	if a.OutletIds != nil {
		for _, o := range *a.OutletIds {
			outlets = append(outlets, string(o))
		}
	}
	return s.roleName(tx, tenant, string(a.RoleId)) + " (" + outletsText(outlets) + ")"
}

// approvalSummary returns the sentence describing the body of operation op filed for path, or "" when
// the operation has nothing in its body that the subject does not already say.
func (s *Service) approvalSummary(tx repository.Tx, tenant, op, path string, body []byte) string {
	var out string
	switch op {
	case "createMember":
		var in gen.CreateMember
		if json.Unmarshal(body, &in) != nil {
			return ""
		}
		out = "new member " + quoted(in.DisplayName)
		if in.MobileE164 != nil {
			out += ", mobile " + maskMobile(string(*in.MobileE164))
		}
		if in.RoleAssignments != nil && len(*in.RoleAssignments) > 0 {
			var rs []string
			for _, a := range *in.RoleAssignments {
				rs = append(rs, s.assignmentText(tx, tenant, a))
			}
			out += ", with " + listText(rs)
		}
	case "updateMember":
		var in gen.UpdateMember
		if json.Unmarshal(body, &in) != nil {
			return ""
		}
		out = "member " + s.memberName(tx, tenant, pathID(path, 3))
		if in.Status != nil {
			out += ", status becomes " + clean(string(*in.Status), 20)
		}
		if in.DisplayName != nil {
			out += ", renamed to " + quoted(*in.DisplayName)
		}
	case "createRoleAssignment":
		var in gen.AssignmentInput
		if json.Unmarshal(body, &in) != nil {
			return ""
		}
		out = "member " + s.memberName(tx, tenant, pathID(path, 3)) + " gets role " + s.assignmentText(tx, tenant, in)
	case "createRole":
		var in gen.RoleInput
		if json.Unmarshal(body, &in) != nil {
			return ""
		}
		out = "new role " + quoted(in.Name) + " with " + s.permissionsText(permStrings(in.Permissions))
	case "updateRole":
		var in gen.RoleInput
		if json.Unmarshal(body, &in) != nil {
			return ""
		}
		id := pathID(path, 3)
		out = "role " + s.roleName(tx, tenant, id)
		if r, _ := get[role](tx, kRole, tenant, id); r != nil {
			if in.Name != "" && in.Name != r.Name {
				out += ", renamed to " + quoted(in.Name)
			}
			added, removed := diff(r.Perms, permStrings(in.Permissions))
			if len(added) > 0 {
				out += ", adds " + listText(added)
			}
			if len(removed) > 0 {
				out += ", removes " + listText(removed)
			}
			if len(added) == 0 && len(removed) == 0 {
				out += ", permissions unchanged"
			}
		} else {
			out += ", with " + s.permissionsText(permStrings(in.Permissions))
		}
	case "createActivationCode":
		var in gen.CreateActivationCode
		if json.Unmarshal(body, &in) != nil {
			return ""
		}
		out = "code for a " + clean(string(in.Kind), 20) + " device at outlet " + clean(string(in.OutletId), 40)
	case "registerDevice":
		var in gen.RegisterDevice
		if json.Unmarshal(body, &in) != nil {
			return ""
		}
		out = clean(string(in.Kind), 20) + " device " + quoted(in.Name) + " at outlet " + clean(string(in.OutletId), 40)
	default:
		return ""
	}
	return out
}

func (s *Service) permissionsText(perms []string) string {
	if len(perms) == 0 {
		return "no permissions"
	}
	for i := range perms {
		perms[i] = clean(perms[i], 60)
	}
	return listText(perms)
}

func permStrings(in []gen.PermissionKey) []string {
	out := make([]string, len(in))
	for i, p := range in {
		out[i] = string(p)
	}
	return out
}

// diff returns what next adds to and removes from before.
func diff(before, next []string) (added, removed []string) {
	have, want := map[string]bool{}, map[string]bool{}
	for _, p := range before {
		have[p] = true
	}
	for _, p := range next {
		want[p] = true
		if !have[p] {
			added = append(added, clean(p, 60))
		}
	}
	for _, p := range before {
		if !want[p] {
			removed = append(removed, clean(p, 60))
		}
	}
	return added, removed
}

// withSummary appends the body summary to the operation's subject, bounded in length.
func withSummary(subject, summary string) string {
	if summary == "" {
		return subject
	}
	out := subject + ": " + summary
	if rs := []rune(out); len(rs) > maxSubject {
		out = string(rs[:maxSubject]) + "..."
	}
	return out
}
