package repository

import "encoding/json"

func scanLabeledAsset(s RowScanner) (LabeledAsset, error) {
	var value LabeledAsset
	var labels []byte
	err := s.Scan(&value.ID, &value.Name, &labels)
	if err != nil {
		return value, opError("scan labeled asset", err)
	}
	err = json.Unmarshal(labels, &value.Labels)
	return value, opError("decode asset labels", err)
}
