package model

type RefreshToken struct {
	Id      string `bson:"id" json:"id,omitempty"`
	TokenId string `bson:"tokenid" json:"token_id,omitempty" validate:"required"`
	Used    bool   `bson:"used" json:"used,omitempty" validate:"required"`
}
