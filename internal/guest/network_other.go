//go:build !linux

package guest

import "errors"

func (d *Daemon) startNetwork(*Session) error { return errors.New("session networking requires Linux") }

func (d *Daemon) attachNetwork(*Session) error {
	return errors.New("session networking requires Linux")
}
func NetworkAttach(string) error         { return errors.New("session networking requires Linux") }
func NetworkWait(string, []string) error { return errors.New("session networking requires Linux") }
