//go:build !linux && !darwin

package main

import "errors"

func writeReviewFile(string, []byte) error  { return errors.New("managed review unsupported") }
func readReviewFile(string) ([]byte, error) { return nil, errors.New("managed review unsupported") }
