package store

import "errors"

var ErrNotFound = errors.New("not found")
var ErrForbidden = errors.New("forbidden")
var ErrConflict = errors.New("conflict")
var ErrInvalidInput = errors.New("invalid input")
