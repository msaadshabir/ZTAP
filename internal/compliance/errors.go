package compliance

import "errors"

func Err(msg string) error {
	return errors.New(msg)
}
