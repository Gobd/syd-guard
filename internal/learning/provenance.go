package learning

import "errors"

// ErrReviewPending means a helper mutation for this project/name has not been
// authenticated as bound or rejected. It must not be treated as manual intent.
var ErrReviewPending = errors.New("learning review outcome is pending or indeterminate")

// ErrCurrentAuthorized identifies separately reviewed current bytes, not proof
// that a prior uncertain learning CAS committed or complete learning coverage.
var ErrCurrentAuthorized = errors.New("current snapshot separately authorized; learning CAS provenance remains unknown")
