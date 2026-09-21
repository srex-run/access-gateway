package repository

import "encoding/json"

const userSummaryColumns = `u.id, u.nickname, u.username, COALESCE(u.email, ''), u.status,
	COALESCE(u.feishu_open_id, '') <> '', u.created_at, COALESCE(u.department, ''), u.labels, u.revision`

func scanUserSummary(s RowScanner) (UserSummary, error) {
	var v UserSummary
	var labels []byte
	err := s.Scan(
		&v.ID,          // id
		&v.Nickname,    // nickname
		&v.Username,    // username
		&v.Email,       // email
		&v.Status,      // status
		&v.FeishuBound, // feishu_bound
		&v.CreatedAt,   // created_at
		&v.Department,  // department
		&labels,        // labels
		&v.Revision,    // revision
	)
	if err != nil {
		return v, opError("scan user directory", err)
	}
	err = json.Unmarshal(labels, &v.Labels)
	return v, opError("decode directory labels", err)
}

func scanAssetApproverSummary(s RowScanner) (AssetApproverSummary, error) {
	var v AssetApproverSummary
	err := s.Scan(
		&v.ID,            // id
		&v.UserID,        // user_id
		&v.Name,          // name
		&v.Username,      // username
		&v.Status,        // status
		&v.FeishuBound,   // feishu_bound
		&v.ApprovalLevel, // approval_level
		&v.Role,          // role
	)
	return v, opError("scan asset approver directory", err)
}
