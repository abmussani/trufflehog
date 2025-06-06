// Code generated by go generate; DO NOT EDIT.
package fastly

import "errors"

type Permission int

const (
    Invalid Permission = iota
    Global Permission = iota
    GlobalRead Permission = iota
    PurgeAll Permission = iota
    PurgeSelect Permission = iota
)

var (
    PermissionStrings = map[Permission]string{
        Global: "global",
        GlobalRead: "global:read",
        PurgeAll: "purge_all",
        PurgeSelect: "purge_select",
    }

    StringToPermission = map[string]Permission{
        "global": Global,
        "global:read": GlobalRead,
        "purge_all": PurgeAll,
        "purge_select": PurgeSelect,
    }

    PermissionIDs = map[Permission]int{
        Global: 1,
        GlobalRead: 2,
        PurgeAll: 3,
        PurgeSelect: 4,
    }

    IdToPermission = map[int]Permission{
        1: Global,
        2: GlobalRead,
        3: PurgeAll,
        4: PurgeSelect,
    }
)

// ToString converts a Permission enum to its string representation
func (p Permission) ToString() (string, error) {
    if str, ok := PermissionStrings[p]; ok {
        return str, nil
    }
    return "", errors.New("invalid permission")
}

// ToID converts a Permission enum to its ID
func (p Permission) ToID() (int, error) {
    if id, ok := PermissionIDs[p]; ok {
        return id, nil
    }
    return 0, errors.New("invalid permission")
}

// PermissionFromString converts a string representation to its Permission enum
func PermissionFromString(s string) (Permission, error) {
    if p, ok := StringToPermission[s]; ok {
        return p, nil
    }
    return 0, errors.New("invalid permission string")
}

// PermissionFromID converts an ID to its Permission enum
func PermissionFromID(id int) (Permission, error) {
    if p, ok := IdToPermission[id]; ok {
        return p, nil
    }
    return 0, errors.New("invalid permission ID")
}
