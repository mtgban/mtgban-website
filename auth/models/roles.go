package models

import (
	"golang.org/x/exp/slices"
)

type UserRole string

const (
	RoleApi     UserRole = "api"
	RoleTest    UserRole = "test"
	RoleFree    UserRole = "free"
	RolePioneer UserRole = "pioneer"
	RoleModern  UserRole = "modern"
	RoleLegacy  UserRole = "legacy"
	RoleVintage UserRole = "vintage"
	RoleAdmin   UserRole = "admin"
)

var RoleHierarchy = map[UserRole][]UserRole{
	RoleFree:    {},
	RolePioneer: {RoleFree},
	RoleModern:  {RoleFree, RolePioneer},
	RoleLegacy:  {RoleFree, RolePioneer, RoleModern},
	RoleVintage: {RoleFree, RolePioneer, RoleModern, RoleLegacy},
	RoleAdmin:   {RoleFree, RolePioneer, RoleModern, RoleLegacy, RoleVintage},
}

func (r UserRole) String() string {
	return string(r)
}

func (r UserRole) FromProductName(productName string) UserRole {
	switch productName {
	case "Pioneer":
		return RolePioneer
	case "Modern":
		return RoleModern
	case "Legacy":
		return RoleLegacy
	case "Vintage":
		return RoleVintage
	default:
		return RoleFree
	}
}

func (r UserRole) IsValid() bool {
	switch r {
	case RoleApi, RoleTest, RoleFree, RolePioneer, RoleModern, RoleLegacy, RoleVintage, RoleAdmin:
		return true
	}
	return false
}

func (r UserRole) IsSubscribed() bool {
	switch r {
	case RoleFree, RolePioneer, RoleModern, RoleLegacy, RoleVintage:
		return true
	default:
		return false
	}
}

func (r UserRole) HasAccess(targetRole UserRole) bool {
	return slices.Contains(RoleHierarchy[r], targetRole)
}
